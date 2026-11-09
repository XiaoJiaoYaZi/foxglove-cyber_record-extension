//! A deliberately small protobuf wire-format decoder.
//!
//! Cyber record files are self-describing only for the outer record protobufs
//! (`Header`, `Index`, `ChunkBody`, ...). We decode those with this module
//! instead of generating code from Apollo's `.proto` files, which keeps the
//! data loader small and free of a protobuf runtime.

use std::fmt;

/// Protobuf wire types.
pub(crate) const WIRE_VARINT: u8 = 0;
pub(crate) const WIRE_FIXED64: u8 = 1;
pub(crate) const WIRE_LEN: u8 = 2;
pub(crate) const WIRE_START_GROUP: u8 = 3;
pub(crate) const WIRE_END_GROUP: u8 = 4;
pub(crate) const WIRE_FIXED32: u8 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecodeError {
    message: String,
}

impl DecodeError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DecodeError {}

type Result<T> = std::result::Result<T, DecodeError>;

/// A cursor over one protobuf message.
pub(crate) struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    /// Read a varint. Protobuf varints are at most 10 bytes and fit in 64 bits.
    pub(crate) fn read_varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        for byte_index in 0..10 {
            let byte = *self
                .bytes
                .get(self.pos)
                .ok_or_else(|| DecodeError::new("truncated varint"))?;
            self.pos += 1;

            if byte_index == 9 && byte > 0x01 {
                return Err(DecodeError::new("varint overflows u64"));
            }
            value |= u64::from(byte & 0x7f) << (byte_index * 7);
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(DecodeError::new("varint is longer than 10 bytes"))
    }

    /// Read a field tag and return `(field_number, wire_type)`.
    pub(crate) fn read_tag(&mut self) -> Result<(u32, u8)> {
        let tag = self.read_varint()?;
        if tag == 0 {
            return Err(DecodeError::new("field tag 0 is invalid"));
        }
        let field = tag >> 3;
        if field == 0 || field > u64::from(u32::MAX) {
            return Err(DecodeError::new("field number is out of range"));
        }
        Ok((field as u32, (tag & 0x07) as u8))
    }

    /// Read a length-delimited field as a borrowed slice.
    pub(crate) fn read_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.read_varint()?;
        let len = usize::try_from(len)
            .map_err(|_| DecodeError::new("length-delimited field is too large"))?;
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| DecodeError::new("length overflow"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| DecodeError::new("truncated length-delimited field"))?;
        self.pos = end;
        Ok(slice)
    }

    /// Read a UTF-8 string, replacing invalid sequences rather than failing.
    /// Topic names in real recordings are UTF-8; being permissive here means a
    /// single malformed name cannot make an entire recording unreadable.
    pub(crate) fn read_string(&mut self) -> Result<String> {
        Ok(String::from_utf8_lossy(self.read_bytes()?).into_owned())
    }

    /// Skip one field's payload.
    pub(crate) fn skip(&mut self, wire_type: u8) -> Result<()> {
        match wire_type {
            WIRE_VARINT => {
                self.read_varint()?;
            }
            WIRE_FIXED64 => self.advance(8)?,
            WIRE_LEN => {
                self.read_bytes()?;
            }
            WIRE_START_GROUP => {
                // Groups are deprecated and do not appear in record.proto, but
                // handling them makes the decoder robust for descriptors and
                // messages that contain unknown group fields.
                let mut depth = 1usize;
                while depth > 0 {
                    let (_, wire) = self.read_tag()?;
                    match wire {
                        WIRE_START_GROUP => depth += 1,
                        WIRE_END_GROUP => depth -= 1,
                        other => self.skip(other)?,
                    }
                }
            }
            WIRE_END_GROUP => {
                return Err(DecodeError::new("unexpected end-group tag"));
            }
            WIRE_FIXED32 => self.advance(4)?,
            other => {
                return Err(DecodeError::new(format!(
                    "unknown protobuf wire type {other}"
                )));
            }
        }
        Ok(())
    }

    fn advance(&mut self, count: usize) -> Result<()> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or_else(|| DecodeError::new("offset overflow"))?;
        if end > self.bytes.len() {
            return Err(DecodeError::new("truncated fixed-width field"));
        }
        self.pos = end;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_multibyte_varints() {
        let mut decoder = Decoder::new(&[0xac, 0x02]);
        assert_eq!(decoder.read_varint().unwrap(), 300);
    }

    #[test]
    fn rejects_truncated_varint() {
        let mut decoder = Decoder::new(&[0x80]);
        assert!(decoder.read_varint().is_err());
    }

    #[test]
    fn skips_unknown_length_delimited_field() {
        let bytes = [0x12, 0x03, b'a', b'b', b'c'];
        let mut decoder = Decoder::new(&bytes);
        let (field, wire) = decoder.read_tag().unwrap();
        assert_eq!((field, wire), (2, WIRE_LEN));
        decoder.skip(wire).unwrap();
        assert!(decoder.is_empty());
    }
}
