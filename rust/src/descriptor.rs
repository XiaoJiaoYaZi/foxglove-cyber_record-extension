//! Converts Apollo Cyber's `ProtoDesc` wrapper into a standard protobuf
//! `FileDescriptorSet`.
//!
//! Cyber stores channel schemas as `apollo.cyber.proto.ProtoDesc`, which has a
//! `bytes desc` field containing a serialized `FileDescriptorProto` plus a
//! recursively nested list of dependencies. Foxglove expects the standard
//! `google.protobuf.FileDescriptorSet` wire format instead, so this module
//! unwraps and re-wraps the descriptors.

use crate::protobuf::{Decoder, WIRE_LEN};

const MAX_DEPENDENCY_DEPTH: usize = 32;

/// Convert a Cyber `ProtoDesc` byte string into a `FileDescriptorSet`.
///
/// The function also accepts an already-serialized `FileDescriptorSet` or a
/// bare `FileDescriptorProto`, which makes it tolerant of recordings produced
/// by tools other than Apollo's `cyber_recorder`.
///
/// Returns an empty vector if `input` does not contain usable descriptors.
pub fn proto_desc_to_file_descriptor_set(input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }

    // Some third-party writers store a bare FileDescriptorProto. Detect this
    // before trying to interpret field 1 as a nested ProtoDesc.
    if looks_like_file_descriptor(input) {
        return wrap_file_descriptor(input);
    }

    let mut files: Vec<&[u8]> = Vec::new();
    collect_descriptors(input, &mut files, 0);

    let mut out = Vec::new();
    for file in files {
        // FileDescriptorSet { repeated FileDescriptorProto file = 1; }
        out.push((1 << 3) | WIRE_LEN);
        write_varint(file.len() as u64, &mut out);
        out.extend_from_slice(file);
    }
    out
}

fn collect_descriptors<'a>(input: &'a [u8], out: &mut Vec<&'a [u8]>, depth: usize) {
    if depth > MAX_DEPENDENCY_DEPTH {
        return;
    }

    let mut decoder = Decoder::new(input);
    let mut descriptors: Vec<&[u8]> = Vec::new();
    let mut dependencies: Vec<&[u8]> = Vec::new();

    while !decoder.is_empty() {
        let Ok((field, wire)) = decoder.read_tag() else {
            break;
        };
        match (field, wire) {
            // ProtoDesc.desc
            (1, WIRE_LEN) => {
                if let Ok(bytes) = decoder.read_bytes()
                    && looks_like_file_descriptor(bytes)
                {
                    descriptors.push(bytes);
                }
            }
            // ProtoDesc.dependencies
            (2, WIRE_LEN) => {
                if let Ok(bytes) = decoder.read_bytes() {
                    dependencies.push(bytes);
                }
            }
            _ => {
                if decoder.skip(wire).is_err() {
                    break;
                }
            }
        }
    }

    // Put dependencies before the file that imports them. This is the order
    // most descriptor pools expect when building a set incrementally.
    for dependency in dependencies {
        collect_descriptors(dependency, out, depth + 1);
    }
    for descriptor in descriptors {
        if !out.contains(&descriptor) {
            out.push(descriptor);
        }
    }
}

fn looks_like_file_descriptor(bytes: &[u8]) -> bool {
    if bytes.len() < 4 {
        return false;
    }
    let mut decoder = Decoder::new(bytes);
    let mut has_name = false;

    while !decoder.is_empty() {
        let Ok((field, wire)) = decoder.read_tag() else {
            return false;
        };
        if field == 1 && wire == WIRE_LEN {
            match decoder.read_bytes() {
                Ok(name) if !name.is_empty() => {
                    // A FileDescriptorProto's file name is a printable path.
                    // Rejecting control bytes avoids confusing a ProtoDesc
                    // (whose field 1 is a nested binary descriptor) with a
                    // bare FileDescriptorProto.
                    if !name.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
                        return false;
                    }
                    has_name = true;
                }
                _ => return false,
            }
        } else if decoder.skip(wire).is_err() {
            return false;
        }
    }
    has_name
}

fn wrap_file_descriptor(file: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(file.len() + 16);
    out.push((1 << 3) | WIRE_LEN);
    write_varint(file.len() as u64, &mut out);
    out.extend_from_slice(file);
    out
}

fn write_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use prost_types::field_descriptor_proto::{Label, Type};
    use prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    };

    fn file(name: &str, package: &str, message: &str, dependency: Option<&str>) -> Vec<u8> {
        FileDescriptorProto {
            name: Some(name.to_string()),
            package: Some(package.to_string()),
            dependency: dependency.map(str::to_string).into_iter().collect(),
            message_type: vec![DescriptorProto {
                name: Some(message.to_string()),
                field: vec![FieldDescriptorProto {
                    name: Some("value".to_string()),
                    number: Some(1),
                    r#type: Some(Type::Double as i32),
                    label: Some(Label::Optional as i32),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        }
        .encode_to_vec()
    }

    fn wrap(desc: &[u8], deps: &[Vec<u8>]) -> Vec<u8> {
        // ProtoDesc { desc = 1; dependencies = 2; }
        let mut out = Vec::new();
        if !desc.is_empty() {
            out.push((1 << 3) | WIRE_LEN);
            write_varint(desc.len() as u64, &mut out);
            out.extend_from_slice(desc);
        }
        for dep in deps {
            out.push((2 << 3) | WIRE_LEN);
            write_varint(dep.len() as u64, &mut out);
            out.extend_from_slice(dep);
        }
        out
    }

    #[test]
    fn unwraps_dependencies_before_the_importing_file() {
        let base = file("base.proto", "example", "Base", None);
        let child = file("child.proto", "example", "Child", Some("base.proto"));
        let wrapped = wrap(&child, &[wrap(&base, &[])]);

        let fds = proto_desc_to_file_descriptor_set(&wrapped);
        let decoded = FileDescriptorSet::decode(fds.as_slice()).unwrap();

        assert_eq!(decoded.file.len(), 2);
        assert_eq!(decoded.file[0].name.as_deref(), Some("base.proto"));
        assert_eq!(decoded.file[1].name.as_deref(), Some("child.proto"));
        assert_eq!(
            decoded.file[1].message_type[0].name.as_deref(),
            Some("Child")
        );
    }

    #[test]
    fn accepts_a_bare_file_descriptor_proto() {
        let fds = proto_desc_to_file_descriptor_set(&file("solo.proto", "p", "Solo", None));
        let decoded = FileDescriptorSet::decode(fds.as_slice()).unwrap();
        assert_eq!(decoded.file.len(), 1);
        assert_eq!(decoded.file[0].name.as_deref(), Some("solo.proto"));
    }

    #[test]
    fn returns_empty_for_garbage() {
        assert!(proto_desc_to_file_descriptor_set(b"not a descriptor").is_empty());
        assert!(proto_desc_to_file_descriptor_set(&[]).is_empty());
    }
}
