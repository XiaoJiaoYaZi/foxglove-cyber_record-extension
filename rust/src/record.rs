//! Reader for Apollo Cyber RT `.record` files.
//!
//! A Cyber record is a sequence of sections, each with a fixed 16-byte header:
//!
//! ```text
//! offset 0                      offset 16
//! +-------------+---------------+-------------------------------+
//! | type: u32   | size: i64     | payload (protobuf, size bytes)|
//! +-------------+---------------+-------------------------------+
//! | 4 bytes pad |               |
//! ```
//!
//! The first section is always a `Header`. Its payload is followed by padding
//! so the next section starts at `16 + 2048`. Channels, chunk headers, and
//! chunk bodies follow. A completed file ends with an index section and the
//! header is rewritten with `is_complete = true` and `index_position`.
//!
//! The section header uses C++ `struct Section` layout, hence the four bytes of
//! padding between the 32-bit enum and the 64-bit size.

use std::collections::BTreeMap;
use std::fmt;
use std::io::{Read, Seek, SeekFrom};

use crate::protobuf::{DecodeError, Decoder, WIRE_LEN, WIRE_VARINT};

pub const SECTION_HEADER: u32 = 0;
pub const SECTION_CHUNK_HEADER: u32 = 1;
pub const SECTION_CHUNK_BODY: u32 = 2;
pub const SECTION_INDEX: u32 = 3;
pub const SECTION_CHANNEL: u32 = 4;

const SECTION_SIZE: u64 = 16;
const HEADER_LENGTH: u64 = 2048;
const FIRST_SECTION_OFFSET: u64 = SECTION_SIZE + HEADER_LENGTH;

/// Parsed Cyber record `Header` protobuf.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Header {
    pub major_version: u32,
    pub minor_version: u32,
    pub compress: u32,
    pub chunk_interval: u64,
    pub segment_interval: u64,
    pub index_position: u64,
    pub chunk_number: u64,
    pub channel_number: u64,
    pub begin_time: u64,
    pub end_time: u64,
    pub message_number: u64,
    pub size: u64,
    pub is_complete: bool,
    pub chunk_raw_size: u64,
    pub segment_raw_size: u64,
}

/// A channel (topic) and its embedded protobuf descriptor.
#[derive(Debug, Clone, Default)]
pub struct ChannelInfo {
    pub name: String,
    pub message_type: String,
    /// Apollo `ProtoDesc` bytes, not a `FileDescriptorSet`.
    pub proto_desc: Vec<u8>,
    pub message_count: u64,
}

/// Location and time range of one chunk body.
#[derive(Debug, Clone, Default)]
pub struct ChunkInfo {
    pub header_offset: u64,
    pub body_offset: u64,
    pub body_size: u64,
    pub begin_time: u64,
    pub end_time: u64,
    pub message_count: u64,
}

/// Everything needed to initialize a Foxglove data loader without reading
/// every message.
#[derive(Debug, Clone, Default)]
pub struct RecordInfo {
    pub header: Header,
    pub channels: Vec<ChannelInfo>,
    pub chunks: Vec<ChunkInfo>,
    pub warnings: Vec<String>,
}

impl RecordInfo {
    pub fn start_time(&self) -> u64 {
        let chunk_start = self.chunks.iter().map(|chunk| chunk.begin_time).min();
        match (self.header.begin_time, chunk_start) {
            (0, None) => 0,
            (0, Some(value)) => value,
            (value, None) => value,
            (value, Some(chunk)) => value.min(chunk),
        }
    }

    pub fn end_time(&self) -> u64 {
        let chunk_end = self.chunks.iter().map(|chunk| chunk.end_time).max();
        match (self.header.end_time, chunk_end) {
            (0, None) => 0,
            (0, Some(value)) => value,
            (value, None) => value,
            (value, Some(chunk)) => value.max(chunk),
        }
    }

    pub fn message_count(&self) -> u64 {
        let channel_total: u64 = self.channels.iter().map(|ch| ch.message_count).sum();
        channel_total.max(self.header.message_number)
    }
}

/// One message stored in a chunk body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMessage {
    pub channel_name: String,
    pub time: u64,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum RecordError {
    Io(std::io::Error),
    Format(String),
    Truncated { offset: u64, what: String },
}

impl RecordError {
    fn format(message: impl Into<String>) -> Self {
        Self::Format(message.into())
    }

    fn truncated(offset: u64, what: impl Into<String>) -> Self {
        Self::Truncated {
            offset,
            what: what.into(),
        }
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::Format(message) => f.write_str(message),
            Self::Truncated { offset, what } => {
                write!(f, "truncated record at byte {offset}: {what}")
            }
        }
    }
}

impl std::error::Error for RecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for RecordError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<DecodeError> for RecordError {
    fn from(value: DecodeError) -> Self {
        Self::Format(value.to_string())
    }
}

type Result<T> = std::result::Result<T, RecordError>;

#[derive(Debug, Clone, Copy)]
struct Section {
    section_type: u32,
    payload_offset: u64,
    size: u64,
}

#[derive(Debug, Clone, Default)]
struct ChunkHeaderCache {
    message_number: u64,
    begin_time: u64,
    end_time: u64,
    raw_size: u64,
}

#[derive(Debug, Clone, Default)]
struct ParsedIndex {
    channels: Vec<ChannelInfo>,
    chunk_headers: Vec<(u64, ChunkHeaderCache)>,
}

/// Read the header, channels, and chunk index of a Cyber record.
///
/// The reader must support seeking. For complete files this function uses the
/// index and does not scan chunk bodies; for interrupted or index-less files it
/// scans sections and counts messages.
pub fn read_record<R: Read + Seek>(reader: &mut R) -> Result<RecordInfo> {
    let file_len = reader.seek(SeekFrom::End(0))?;
    if file_len < FIRST_SECTION_OFFSET {
        return Err(RecordError::truncated(
            file_len,
            "file is smaller than the 2064-byte record header",
        ));
    }

    let header_section = read_section(reader, 0, file_len)?;
    if header_section.section_type != SECTION_HEADER {
        return Err(RecordError::format(format!(
            "expected SECTION_HEADER (0) at byte 0, found section type {}",
            header_section.section_type
        )));
    }
    if header_section.size > HEADER_LENGTH {
        return Err(RecordError::format(format!(
            "header payload is {} bytes, larger than the {HEADER_LENGTH}-byte header area",
            header_section.size
        )));
    }

    let header_payload = read_payload_vec(reader, header_section, file_len)?;
    let header = parse_header(&header_payload)?;
    let mut warnings = Vec::new();

    if header.major_version != 1 {
        warnings.push(format!(
            "Unsupported Cyber record major version {} (expected 1); attempting to read anyway",
            header.major_version
        ));
    }
    if header.compress != 0 {
        warnings.push(format!(
            "Record header declares compression type {}; this reader only supports uncompressed chunks",
            header.compress
        ));
    }

    let mut channels: Vec<ChannelInfo>;
    let mut chunks: Vec<ChunkInfo>;
    let indexed = if header.is_complete && header.index_position > 0 {
        match read_index(reader, file_len, &header) {
            Ok(index) => {
                if index.channels.is_empty() && header.channel_number > 0 {
                    warnings.push(
                        "Record index did not contain channel metadata; falling back to a section scan"
                            .to_string(),
                    );
                    None
                } else if index.chunk_headers.is_empty() && header.chunk_number > 0 {
                    warnings.push(
                        "Record index did not contain chunk metadata; falling back to a section scan"
                            .to_string(),
                    );
                    None
                } else {
                    Some(index)
                }
            }
            Err(error) => {
                warnings.push(format!(
                    "Could not read the record index ({error}); falling back to a section scan"
                ));
                None
            }
        }
    } else {
        None
    };

    if let Some(index) = indexed {
        channels = merge_channels(index.channels);
        let expected_chunks = index.chunk_headers.len();
        chunks = Vec::with_capacity(expected_chunks);
        for (position, cache) in index.chunk_headers {
            match read_chunk_info(reader, file_len, position, cache) {
                Ok(chunk) => chunks.push(chunk),
                Err(error) => {
                    warnings.push(format!(
                        "Could not read chunk header at byte {position}: {error}; falling back to a section scan"
                    ));
                    chunks.clear();
                    break;
                }
            }
        }
        if chunks.len() != expected_chunks {
            let (scanned_channels, scanned_chunks) =
                scan_sections(reader, file_len, &mut warnings)?;
            channels = scanned_channels;
            chunks = scanned_chunks;
        }
    } else {
        let (scanned_channels, scanned_chunks) = scan_sections(reader, file_len, &mut warnings)?;
        channels = scanned_channels;
        chunks = scanned_chunks;
    }

    chunks.sort_by_key(|chunk| (chunk.begin_time, chunk.end_time, chunk.body_offset));

    if chunks.is_empty() && header.message_number > 0 {
        warnings.push(format!(
            "Header reports {} messages but no readable chunk bodies were found",
            header.message_number
        ));
    }

    Ok(RecordInfo {
        header,
        channels,
        chunks,
        warnings,
    })
}

/// Read and decode all messages from one chunk body.
pub fn read_chunk<R: Read + Seek>(reader: &mut R, chunk: &ChunkInfo) -> Result<Vec<RawMessage>> {
    let file_len = reader.seek(SeekFrom::End(0))?;
    let section = read_section(reader, chunk.body_offset, file_len)?;
    if section.section_type != SECTION_CHUNK_BODY {
        return Err(RecordError::format(format!(
            "expected SECTION_CHUNK_BODY (2) at byte {}, found section type {}",
            chunk.body_offset, section.section_type
        )));
    }
    let payload = read_payload_vec(reader, section, file_len)?;
    let mut messages = Vec::new();
    decode_chunk_body(&payload, |channel_name, time, data| {
        messages.push(RawMessage {
            channel_name: channel_name.to_string(),
            time,
            data: data.to_vec(),
        });
    })?;
    Ok(messages)
}

fn read_index<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    header: &Header,
) -> Result<ParsedIndex> {
    if header.index_position >= file_len {
        return Err(RecordError::truncated(
            header.index_position,
            "index position is outside the file",
        ));
    }
    let section = read_section(reader, header.index_position, file_len)?;
    if section.section_type != SECTION_INDEX {
        return Err(RecordError::format(format!(
            "expected SECTION_INDEX (3) at byte {}, found section type {}",
            header.index_position, section.section_type
        )));
    }
    let payload = read_payload_vec(reader, section, file_len)?;
    parse_index(&payload)
}

fn read_chunk_info<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    header_position: u64,
    cache: ChunkHeaderCache,
) -> Result<ChunkInfo> {
    let header_section = read_section(reader, header_position, file_len)?;
    if header_section.section_type != SECTION_CHUNK_HEADER {
        return Err(RecordError::format(format!(
            "expected SECTION_CHUNK_HEADER (1) at byte {header_position}, found {}",
            header_section.section_type
        )));
    }
    let header_payload = read_payload_vec(reader, header_section, file_len)?;
    let parsed = parse_chunk_header(&header_payload)?;

    let body_offset = header_section
        .payload_offset
        .checked_add(header_section.size)
        .ok_or_else(|| RecordError::format("chunk body offset overflow"))?;
    let body_section = read_section(reader, body_offset, file_len)?;
    if body_section.section_type != SECTION_CHUNK_BODY {
        return Err(RecordError::format(format!(
            "expected SECTION_CHUNK_BODY (2) at byte {body_offset}, found {}",
            body_section.section_type
        )));
    }

    let begin_time = nonzero(parsed.begin_time, cache.begin_time);
    let end_time = nonzero(parsed.end_time, cache.end_time);
    let message_count = nonzero(parsed.message_number, cache.message_number);

    Ok(ChunkInfo {
        header_offset: header_position,
        body_offset,
        body_size: body_section.size,
        begin_time,
        end_time,
        message_count,
    })
}

fn nonzero(primary: u64, fallback: u64) -> u64 {
    if primary != 0 { primary } else { fallback }
}

fn scan_sections<R: Read + Seek>(
    reader: &mut R,
    file_len: u64,
    warnings: &mut Vec<String>,
) -> Result<(Vec<ChannelInfo>, Vec<ChunkInfo>)> {
    warnings.push(
        "Record has no usable index; scanned every section to build the channel and chunk list"
            .to_string(),
    );

    let mut channels: BTreeMap<String, ChannelInfo> = BTreeMap::new();
    let mut chunks = Vec::new();
    let mut pending_header: Option<(ChunkHeaderCache, u64)> = None;
    let mut offset = FIRST_SECTION_OFFSET;

    'sections: while offset.saturating_add(SECTION_SIZE) <= file_len {
        let section = match read_section(reader, offset, file_len) {
            Ok(section) => section,
            Err(error) => {
                warnings.push(format!("Stopped scanning at byte {offset}: {error}"));
                break;
            }
        };

        match section.section_type {
            SECTION_CHANNEL => {
                let payload = match read_payload_vec(reader, section, file_len) {
                    Ok(payload) => payload,
                    Err(error) => {
                        warnings.push(format!(
                            "Stopped scanning at channel section {offset}: {error}"
                        ));
                        break;
                    }
                };
                match parse_channel(&payload) {
                    Ok(channel) => merge_channel(&mut channels, channel),
                    Err(error) => warnings.push(format!(
                        "Ignoring malformed channel section at byte {offset}: {error}"
                    )),
                }
            }
            SECTION_CHUNK_HEADER => {
                let payload = match read_payload_vec(reader, section, file_len) {
                    Ok(payload) => payload,
                    Err(error) => {
                        warnings.push(format!(
                            "Stopped scanning at chunk header {offset}: {error}"
                        ));
                        break;
                    }
                };
                match parse_chunk_header(&payload) {
                    Ok(header) => pending_header = Some((header, section.payload_offset)),
                    Err(error) => {
                        pending_header = None;
                        warnings.push(format!(
                            "Ignoring malformed chunk header at byte {offset}: {error}"
                        ));
                    }
                }
            }
            SECTION_CHUNK_BODY => {
                let payload = match read_payload_vec(reader, section, file_len) {
                    Ok(payload) => payload,
                    Err(error) => {
                        warnings.push(format!("Stopped scanning at chunk body {offset}: {error}"));
                        break;
                    }
                };
                let mut counts: BTreeMap<String, u64> = BTreeMap::new();
                let mut first_time = u64::MAX;
                let mut last_time = 0u64;
                let mut message_count = 0u64;

                if let Err(error) = decode_chunk_body(&payload, |name, time, _data| {
                    if name.is_empty() {
                        return;
                    }
                    *counts.entry(name.to_string()).or_insert(0) += 1;
                    first_time = first_time.min(time);
                    last_time = last_time.max(time);
                    message_count += 1;
                }) {
                    warnings.push(format!(
                        "Stopped scanning at malformed chunk body {offset}: {error}"
                    ));
                    break 'sections;
                }

                for (name, count) in counts {
                    let channel = channels.entry(name.clone()).or_insert_with(|| ChannelInfo {
                        name: name.clone(),
                        ..ChannelInfo::default()
                    });
                    channel.message_count += count;
                }

                let derived_begin = if first_time == u64::MAX {
                    0
                } else {
                    first_time
                };
                let (begin_time, end_time, header_count, header_offset) =
                    match pending_header.take() {
                        Some((header, header_offset)) => (
                            nonzero(header.begin_time, derived_begin),
                            nonzero(header.end_time, last_time),
                            nonzero(header.message_number, message_count),
                            header_offset,
                        ),
                        None => (derived_begin, last_time, message_count, 0),
                    };

                chunks.push(ChunkInfo {
                    header_offset,
                    body_offset: section.payload_offset,
                    body_size: section.size,
                    begin_time,
                    end_time,
                    message_count: header_count,
                });
            }
            SECTION_INDEX => break,
            SECTION_HEADER => {
                warnings.push(format!(
                    "Ignoring unexpected second header section at byte {offset}"
                ));
            }
            other => {
                warnings.push(format!(
                    "Ignoring unknown section type {other} at byte {offset}"
                ));
            }
        }

        offset = section
            .payload_offset
            .checked_add(section.size)
            .ok_or_else(|| RecordError::format("section offset overflow"))?;
        if offset <= section.payload_offset {
            return Err(RecordError::format("section did not advance"));
        }
    }

    Ok((channels.into_values().collect(), chunks))
}

fn read_section<R: Read + Seek>(reader: &mut R, offset: u64, file_len: u64) -> Result<Section> {
    let end = offset
        .checked_add(SECTION_SIZE)
        .ok_or_else(|| RecordError::format("section header offset overflow"))?;
    if end > file_len {
        return Err(RecordError::truncated(offset, "16-byte section header"));
    }

    let mut header = [0u8; 16];
    read_exact_at(reader, offset, &mut header)?;
    let section_type = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let size = i64::from_le_bytes(header[8..16].try_into().unwrap());
    if size < 0 {
        return Err(RecordError::format(format!(
            "negative section size {size} at byte {offset}"
        )));
    }
    let size = size as u64;
    let payload_offset = offset
        .checked_add(SECTION_SIZE)
        .ok_or_else(|| RecordError::format("section payload offset overflow"))?;
    let payload_end = payload_offset
        .checked_add(size)
        .ok_or_else(|| RecordError::format("section payload end overflow"))?;
    if payload_end > file_len {
        return Err(RecordError::truncated(
            offset,
            format!("section payload ends at {payload_end}, beyond file size {file_len}"),
        ));
    }

    Ok(Section {
        section_type,
        payload_offset,
        size,
    })
}

fn read_payload_vec<R: Read + Seek>(
    reader: &mut R,
    section: Section,
    file_len: u64,
) -> Result<Vec<u8>> {
    let end = section
        .payload_offset
        .checked_add(section.size)
        .ok_or_else(|| RecordError::format("payload end overflow"))?;
    if end > file_len {
        return Err(RecordError::truncated(section.payload_offset, "payload"));
    }
    let len = usize::try_from(section.size)
        .map_err(|_| RecordError::format("payload is too large for this platform"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(len)
        .map_err(|_| RecordError::format(format!("cannot allocate {len} bytes for a section")))?;
    bytes.resize(len, 0);
    read_exact_at(reader, section.payload_offset, &mut bytes)?;
    Ok(bytes)
}

fn read_exact_at<R: Read + Seek>(reader: &mut R, offset: u64, buf: &mut [u8]) -> Result<()> {
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(buf)?;
    Ok(())
}

fn parse_header(payload: &[u8]) -> Result<Header> {
    let mut header = Header::default();
    let mut decoder = Decoder::new(payload);

    while !decoder.is_empty() {
        let (field, wire) = decoder.read_tag()?;
        match (field, wire) {
            (1, WIRE_VARINT) => header.major_version = read_u32(&mut decoder)?,
            (2, WIRE_VARINT) => header.minor_version = read_u32(&mut decoder)?,
            (3, WIRE_VARINT) => header.compress = read_u32(&mut decoder)?,
            (4, WIRE_VARINT) => header.chunk_interval = decoder.read_varint()?,
            (5, WIRE_VARINT) => header.segment_interval = decoder.read_varint()?,
            (6, WIRE_VARINT) => header.index_position = decoder.read_varint()?,
            (7, WIRE_VARINT) => header.chunk_number = decoder.read_varint()?,
            (8, WIRE_VARINT) => header.channel_number = decoder.read_varint()?,
            (9, WIRE_VARINT) => header.begin_time = decoder.read_varint()?,
            (10, WIRE_VARINT) => header.end_time = decoder.read_varint()?,
            (11, WIRE_VARINT) => header.message_number = decoder.read_varint()?,
            (12, WIRE_VARINT) => header.size = decoder.read_varint()?,
            (13, WIRE_VARINT) => header.is_complete = decoder.read_varint()? != 0,
            (14, WIRE_VARINT) => header.chunk_raw_size = decoder.read_varint()?,
            (15, WIRE_VARINT) => header.segment_raw_size = decoder.read_varint()?,
            // map_info (16) and vehicle_info (17) are metadata we do not use.
            _ => decoder.skip(wire)?,
        }
    }
    Ok(header)
}

fn read_u32(decoder: &mut Decoder<'_>) -> Result<u32> {
    let value = decoder.read_varint()?;
    Ok(u32::try_from(value).unwrap_or(u32::MAX))
}

fn parse_channel(payload: &[u8]) -> Result<ChannelInfo> {
    let mut channel = ChannelInfo::default();
    let mut decoder = Decoder::new(payload);

    while !decoder.is_empty() {
        let (field, wire) = decoder.read_tag()?;
        match (field, wire) {
            (1, WIRE_LEN) => channel.name = decoder.read_string()?,
            (2, WIRE_LEN) => channel.message_type = decoder.read_string()?,
            (3, WIRE_LEN) => channel.proto_desc = decoder.read_bytes()?.to_vec(),
            _ => decoder.skip(wire)?,
        }
    }
    Ok(channel)
}

fn parse_chunk_header(payload: &[u8]) -> Result<ChunkHeaderCache> {
    let mut header = ChunkHeaderCache::default();
    let mut decoder = Decoder::new(payload);

    while !decoder.is_empty() {
        let (field, wire) = decoder.read_tag()?;
        match (field, wire) {
            (1, WIRE_VARINT) => header.begin_time = decoder.read_varint()?,
            (2, WIRE_VARINT) => header.end_time = decoder.read_varint()?,
            (3, WIRE_VARINT) => header.message_number = decoder.read_varint()?,
            (4, WIRE_VARINT) => header.raw_size = decoder.read_varint()?,
            _ => decoder.skip(wire)?,
        }
    }
    Ok(header)
}

fn parse_index(payload: &[u8]) -> Result<ParsedIndex> {
    let mut index = ParsedIndex::default();
    let mut decoder = Decoder::new(payload);

    while !decoder.is_empty() {
        let (field, wire) = decoder.read_tag()?;
        if field == 1 && wire == WIRE_LEN {
            let entry = decoder.read_bytes()?;
            parse_single_index(entry, &mut index)?;
        } else {
            decoder.skip(wire)?;
        }
    }
    Ok(index)
}

fn parse_single_index(payload: &[u8], index: &mut ParsedIndex) -> Result<()> {
    let mut section_type = 0u32;
    let mut position = 0u64;
    let mut channel = None;
    let mut chunk_header = None;

    let mut decoder = Decoder::new(payload);
    while !decoder.is_empty() {
        let (field, wire) = decoder.read_tag()?;
        match (field, wire) {
            (1, WIRE_VARINT) => section_type = read_u32(&mut decoder)?,
            (2, WIRE_VARINT) => position = decoder.read_varint()?,
            (101, WIRE_LEN) => {
                let bytes = decoder.read_bytes()?;
                channel = Some(parse_channel_cache(bytes)?);
            }
            (102, WIRE_LEN) => {
                let bytes = decoder.read_bytes()?;
                chunk_header = Some(parse_chunk_header_cache(bytes)?);
            }
            _ => decoder.skip(wire)?,
        }
    }

    if section_type == SECTION_CHANNEL {
        if let Some(channel) = channel {
            index.channels.push(channel);
        }
    } else if section_type == SECTION_CHUNK_HEADER
        && let Some(chunk_header) = chunk_header
    {
        index.chunk_headers.push((position, chunk_header));
    }
    Ok(())
}

fn parse_channel_cache(payload: &[u8]) -> Result<ChannelInfo> {
    let mut channel = ChannelInfo::default();
    let mut decoder = Decoder::new(payload);

    while !decoder.is_empty() {
        let (field, wire) = decoder.read_tag()?;
        match (field, wire) {
            (1, WIRE_VARINT) => channel.message_count = decoder.read_varint()?,
            (2, WIRE_LEN) => channel.name = decoder.read_string()?,
            (3, WIRE_LEN) => channel.message_type = decoder.read_string()?,
            (4, WIRE_LEN) => channel.proto_desc = decoder.read_bytes()?.to_vec(),
            _ => decoder.skip(wire)?,
        }
    }
    Ok(channel)
}

fn parse_chunk_header_cache(payload: &[u8]) -> Result<ChunkHeaderCache> {
    let mut header = ChunkHeaderCache::default();
    let mut decoder = Decoder::new(payload);

    while !decoder.is_empty() {
        let (field, wire) = decoder.read_tag()?;
        match (field, wire) {
            (1, WIRE_VARINT) => header.message_number = decoder.read_varint()?,
            (2, WIRE_VARINT) => header.begin_time = decoder.read_varint()?,
            (3, WIRE_VARINT) => header.end_time = decoder.read_varint()?,
            (4, WIRE_VARINT) => header.raw_size = decoder.read_varint()?,
            _ => decoder.skip(wire)?,
        }
    }
    Ok(header)
}

fn merge_channels(channels: Vec<ChannelInfo>) -> Vec<ChannelInfo> {
    let mut by_name: BTreeMap<String, ChannelInfo> = BTreeMap::new();
    for channel in channels {
        merge_channel(&mut by_name, channel);
    }
    by_name.into_values().collect()
}

fn merge_channel(by_name: &mut BTreeMap<String, ChannelInfo>, channel: ChannelInfo) {
    if channel.name.is_empty() {
        return;
    }
    match by_name.get_mut(&channel.name) {
        Some(existing) => {
            existing.message_count = existing.message_count.saturating_add(channel.message_count);
            if existing.message_type.is_empty() {
                existing.message_type = channel.message_type;
            }
            if existing.proto_desc.is_empty() {
                existing.proto_desc = channel.proto_desc;
            }
        }
        None => {
            by_name.insert(channel.name.clone(), channel);
        }
    }
}

fn decode_chunk_body(payload: &[u8], mut on_message: impl FnMut(&str, u64, &[u8])) -> Result<()> {
    let mut decoder = Decoder::new(payload);
    while !decoder.is_empty() {
        let (field, wire) = decoder.read_tag()?;
        if field == 1 && wire == WIRE_LEN {
            let message = decoder.read_bytes()?;
            decode_single_message(message, &mut on_message)?;
        } else {
            decoder.skip(wire)?;
        }
    }
    Ok(())
}

fn decode_single_message(
    payload: &[u8],
    on_message: &mut impl FnMut(&str, u64, &[u8]),
) -> Result<()> {
    let mut channel_name = String::new();
    let mut time = 0u64;
    let mut data: &[u8] = &[];

    let mut decoder = Decoder::new(payload);
    while !decoder.is_empty() {
        let (field, wire) = decoder.read_tag()?;
        match (field, wire) {
            (1, WIRE_LEN) => channel_name = decoder.read_string()?,
            (2, WIRE_VARINT) => time = decoder.read_varint()?,
            (3, WIRE_LEN) => data = decoder.read_bytes()?,
            _ => decoder.skip(wire)?,
        }
    }

    on_message(&channel_name, time, data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use prost::Message;
    use prost_types::{DescriptorProto, FileDescriptorProto};

    fn varint(value: u64, out: &mut Vec<u8>) {
        let mut value = value;
        while value >= 0x80 {
            out.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn key(field: u32, wire: u8, out: &mut Vec<u8>) {
        varint(u64::from(field) << 3 | u64::from(wire), out);
    }

    fn bytes_field(field: u32, value: &[u8], out: &mut Vec<u8>) {
        key(field, WIRE_LEN, out);
        varint(value.len() as u64, out);
        out.extend_from_slice(value);
    }

    fn string_field(field: u32, value: &str, out: &mut Vec<u8>) {
        bytes_field(field, value.as_bytes(), out);
    }

    fn uint_field(field: u32, value: u64, out: &mut Vec<u8>) {
        key(field, WIRE_VARINT, out);
        varint(value, out);
    }

    fn section(section_type: u32, payload: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&section_type.to_le_bytes());
        out.extend_from_slice(&[0u8; 4]);
        out.extend_from_slice(&(payload.len() as i64).to_le_bytes());
        out.extend_from_slice(payload);
    }

    fn proto_desc() -> Vec<u8> {
        let file = FileDescriptorProto {
            name: Some("test.proto".to_string()),
            package: Some("test".to_string()),
            message_type: vec![DescriptorProto {
                name: Some("Thing".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec();
        let mut desc = Vec::new();
        bytes_field(1, &file, &mut desc);
        desc
    }

    struct FixtureChannel {
        name: &'static str,
        message_type: &'static str,
        proto_desc: Vec<u8>,
    }

    struct FixtureChunk {
        messages: Vec<(&'static str, u64, Vec<u8>)>,
    }

    fn build_record(
        channels: &[FixtureChannel],
        chunks: &[FixtureChunk],
        complete: bool,
    ) -> Vec<u8> {
        // Body starts after the 2064-byte header area.
        let mut body = Vec::new();
        let mut channel_positions = Vec::new();
        for channel in channels {
            let position = FIRST_SECTION_OFFSET + body.len() as u64;
            let mut payload = Vec::new();
            string_field(1, channel.name, &mut payload);
            string_field(2, channel.message_type, &mut payload);
            bytes_field(3, &channel.proto_desc, &mut payload);
            section(SECTION_CHANNEL, &payload, &mut body);
            channel_positions.push((position, channel));
        }

        let mut chunk_positions = Vec::new();
        for chunk in chunks {
            let header_position = FIRST_SECTION_OFFSET + body.len() as u64;
            let begin = chunk.messages.iter().map(|m| m.1).min().unwrap_or(0);
            let end = chunk.messages.iter().map(|m| m.1).max().unwrap_or(0);
            let mut header_payload = Vec::new();
            uint_field(1, begin, &mut header_payload);
            uint_field(2, end, &mut header_payload);
            uint_field(3, chunk.messages.len() as u64, &mut header_payload);
            uint_field(
                4,
                chunk.messages.iter().map(|m| m.2.len() as u64).sum(),
                &mut header_payload,
            );
            section(SECTION_CHUNK_HEADER, &header_payload, &mut body);

            let body_position = FIRST_SECTION_OFFSET + body.len() as u64;
            let mut body_payload = Vec::new();
            for (channel, time, data) in &chunk.messages {
                let mut message = Vec::new();
                string_field(1, channel, &mut message);
                uint_field(2, *time, &mut message);
                bytes_field(3, data, &mut message);
                bytes_field(1, &message, &mut body_payload);
            }
            section(SECTION_CHUNK_BODY, &body_payload, &mut body);
            chunk_positions.push((
                header_position,
                body_position,
                begin,
                end,
                chunk.messages.len() as u64,
            ));
        }

        let index_position = FIRST_SECTION_OFFSET + body.len() as u64;
        let mut index_payload = Vec::new();
        if complete {
            for (position, channel) in &channel_positions {
                let count = chunks
                    .iter()
                    .flat_map(|chunk| chunk.messages.iter())
                    .filter(|(name, _, _)| *name == channel.name)
                    .count() as u64;
                let mut cache = Vec::new();
                uint_field(1, count, &mut cache);
                string_field(2, channel.name, &mut cache);
                string_field(3, channel.message_type, &mut cache);
                bytes_field(4, &channel.proto_desc, &mut cache);
                let mut entry = Vec::new();
                uint_field(1, u64::from(SECTION_CHANNEL), &mut entry);
                uint_field(2, *position, &mut entry);
                bytes_field(101, &cache, &mut entry);
                bytes_field(1, &entry, &mut index_payload);
            }
            for (header_position, _body_position, begin, end, count) in &chunk_positions {
                let mut cache = Vec::new();
                uint_field(1, *count, &mut cache);
                uint_field(2, *begin, &mut cache);
                uint_field(3, *end, &mut cache);
                uint_field(4, 10, &mut cache);
                let mut entry = Vec::new();
                uint_field(1, u64::from(SECTION_CHUNK_HEADER), &mut entry);
                uint_field(2, *header_position, &mut entry);
                bytes_field(102, &cache, &mut entry);
                bytes_field(1, &entry, &mut index_payload);
            }
        }

        let mut index_section = Vec::new();
        if complete {
            section(SECTION_INDEX, &index_payload, &mut index_section);
        }

        let total_size = FIRST_SECTION_OFFSET + body.len() as u64 + index_section.len() as u64;
        let begin_time = chunks
            .iter()
            .flat_map(|chunk| chunk.messages.iter().map(|m| m.1))
            .min()
            .unwrap_or(0);
        let end_time = chunks
            .iter()
            .flat_map(|chunk| chunk.messages.iter().map(|m| m.1))
            .max()
            .unwrap_or(0);
        let message_count: u64 = chunks.iter().map(|chunk| chunk.messages.len() as u64).sum();

        let mut header_payload = Vec::new();
        uint_field(1, 1, &mut header_payload);
        uint_field(2, 0, &mut header_payload);
        uint_field(3, 0, &mut header_payload);
        uint_field(4, 20_000_000_000, &mut header_payload);
        uint_field(5, 60_000_000_000, &mut header_payload);
        uint_field(
            6,
            if complete { index_position } else { 0 },
            &mut header_payload,
        );
        uint_field(7, chunks.len() as u64, &mut header_payload);
        uint_field(8, channels.len() as u64, &mut header_payload);
        uint_field(9, begin_time, &mut header_payload);
        uint_field(10, end_time, &mut header_payload);
        uint_field(11, message_count, &mut header_payload);
        uint_field(12, total_size, &mut header_payload);
        if complete {
            uint_field(13, 1, &mut header_payload);
        }

        assert!(header_payload.len() <= HEADER_LENGTH as usize);
        let mut file = Vec::with_capacity(total_size as usize);
        section(SECTION_HEADER, &header_payload, &mut file);
        file.resize(FIRST_SECTION_OFFSET as usize, 0);
        file.extend_from_slice(&body);
        file.extend_from_slice(&index_section);
        file
    }

    fn fixture() -> Vec<u8> {
        build_record(
            &[
                FixtureChannel {
                    name: "/chassis",
                    message_type: "test.Chassis",
                    proto_desc: proto_desc(),
                },
                FixtureChannel {
                    name: "/image",
                    message_type: "test.Image",
                    proto_desc: proto_desc(),
                },
            ],
            &[
                FixtureChunk {
                    messages: vec![
                        ("/chassis", 1_000_000_000, vec![1, 2, 3]),
                        ("/image", 1_500_000_000, vec![4, 5, 6, 7]),
                    ],
                },
                FixtureChunk {
                    messages: vec![("/chassis", 2_000_000_000, vec![8, 9])],
                },
            ],
            true,
        )
    }

    #[test]
    fn parses_complete_record_from_index() {
        let bytes = fixture();
        let mut cursor = Cursor::new(bytes);
        let info = read_record(&mut cursor).unwrap();

        assert_eq!(info.header.major_version, 1);
        assert!(info.header.is_complete);
        assert_eq!(info.channels.len(), 2);
        assert_eq!(info.channels[0].name, "/chassis");
        assert_eq!(info.channels[0].message_count, 2);
        assert_eq!(info.channels[1].name, "/image");
        assert_eq!(info.channels[1].message_count, 1);
        assert_eq!(info.chunks.len(), 2);
        assert_eq!(info.start_time(), 1_000_000_000);
        assert_eq!(info.end_time(), 2_000_000_000);
        assert_eq!(info.message_count(), 3);
        assert!(!info.channels[0].proto_desc.is_empty());
    }

    #[test]
    fn parses_incomplete_record_without_index() {
        let bytes = build_record(
            &[FixtureChannel {
                name: "/chassis",
                message_type: "test.Chassis",
                proto_desc: proto_desc(),
            }],
            &[FixtureChunk {
                messages: vec![("/chassis", 42, vec![9, 8, 7])],
            }],
            false,
        );
        let mut cursor = Cursor::new(bytes);
        let info = read_record(&mut cursor).unwrap();

        assert!(!info.header.is_complete);
        assert_eq!(info.channels.len(), 1);
        assert_eq!(info.channels[0].message_count, 1);
        assert_eq!(info.chunks.len(), 1);
        assert_eq!(info.start_time(), 42);
        assert!(
            info.warnings
                .iter()
                .any(|warning| warning.contains("no usable index"))
        );
    }

    #[test]
    fn reads_chunk_messages() {
        let bytes = fixture();
        let mut cursor = Cursor::new(bytes);
        let info = read_record(&mut cursor).unwrap();
        let messages = read_chunk(&mut cursor, &info.chunks[0]).unwrap();

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].channel_name, "/chassis");
        assert_eq!(messages[0].time, 1_000_000_000);
        assert_eq!(messages[0].data, vec![1, 2, 3]);
        assert_eq!(messages[1].channel_name, "/image");
        assert_eq!(messages[1].data, vec![4, 5, 6, 7]);
    }

    #[test]
    fn rejects_non_record_files() {
        let mut cursor = Cursor::new(vec![0u8; 4096]);
        assert!(read_record(&mut cursor).is_err());
    }
}
