//! Create a small, valid Cyber record for trying the Foxglove extension.
//!
//! ```sh
//! cargo run --example make_demo_record -- demo.record
//! cargo run --example inspect -- demo.record
//! ```

use std::env;
use std::fs::File;
use std::io::Write;

use prost::Message;
use prost_types::field_descriptor_proto::{Label, Type};
use prost_types::{DescriptorProto, FieldDescriptorProto, FileDescriptorProto};

const SECTION_HEADER: u32 = 0;
const SECTION_CHUNK_HEADER: u32 = 1;
const SECTION_CHUNK_BODY: u32 = 2;
const SECTION_INDEX: u32 = 3;
const SECTION_CHANNEL: u32 = 4;
const SECTION_SIZE: u64 = 16;
const HEADER_LENGTH: u64 = 2048;
const FIRST_SECTION_OFFSET: u64 = SECTION_SIZE + HEADER_LENGTH;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "demo.record".to_string());
    let bytes = build_demo_record();
    let mut file = File::create(&path)?;
    file.write_all(&bytes)?;
    println!("wrote {path} ({} bytes)", bytes.len());
    Ok(())
}

fn build_demo_record() -> Vec<u8> {
    let descriptor = descriptor();
    let mut proto_desc = Vec::new();
    bytes_field(1, &descriptor, &mut proto_desc);

    let channels: [(&str, &str, &[u8]); 2] = [
        ("/demo/point", "demo.Point", &proto_desc),
        ("/demo/status", "demo.Status", &proto_desc),
    ];

    let mut chunks: Vec<Vec<(&str, u64, Vec<u8>)>> = Vec::new();
    for chunk_index in 0..3u64 {
        let mut messages = Vec::new();
        for i in 0..5u64 {
            let time = 1_700_000_000_000_000_000 + (chunk_index * 5 + i) * 100_000_000;
            let x = (chunk_index * 5 + i) as f64;
            let mut point = Vec::new();
            fixed64_field(1, x, &mut point);
            fixed64_field(2, x * 2.0, &mut point);
            string_field(3, &format!("point-{x}"), &mut point);
            messages.push(("/demo/point", time, point));

            let mut status = Vec::new();
            uint_field(1, u64::from(i % 2 == 0), &mut status);
            string_field(2, if i % 2 == 0 { "ok" } else { "busy" }, &mut status);
            uint_field(3, i, &mut status);
            messages.push(("/demo/status", time + 10_000_000, status));
        }
        chunks.push(messages);
    }

    build_record(&channels, &chunks)
}

fn descriptor() -> Vec<u8> {
    FileDescriptorProto {
        name: Some("demo.proto".to_string()),
        package: Some("demo".to_string()),
        syntax: Some("proto3".to_string()),
        message_type: vec![
            DescriptorProto {
                name: Some("Point".to_string()),
                field: vec![
                    field("x", 1, Type::Double),
                    field("y", 2, Type::Double),
                    field("label", 3, Type::String),
                ],
                ..Default::default()
            },
            DescriptorProto {
                name: Some("Status".to_string()),
                field: vec![
                    field("ok", 1, Type::Bool),
                    field("text", 2, Type::String),
                    field("count", 3, Type::Int64),
                ],
                ..Default::default()
            },
        ],
        ..Default::default()
    }
    .encode_to_vec()
}

fn field(name: &str, number: i32, field_type: Type) -> FieldDescriptorProto {
    FieldDescriptorProto {
        name: Some(name.to_string()),
        number: Some(number),
        r#type: Some(field_type as i32),
        label: Some(Label::Optional as i32),
        json_name: Some(name.to_string()),
        ..Default::default()
    }
}

fn build_record(channels: &[(&str, &str, &[u8])], chunks: &[Vec<(&str, u64, Vec<u8>)>]) -> Vec<u8> {
    let mut body = Vec::new();
    let mut channel_positions = Vec::new();
    for (name, message_type, desc) in channels {
        let position = FIRST_SECTION_OFFSET + body.len() as u64;
        let mut payload = Vec::new();
        string_field(1, name, &mut payload);
        string_field(2, message_type, &mut payload);
        bytes_field(3, desc, &mut payload);
        section(SECTION_CHANNEL, &payload, &mut body);
        channel_positions.push((position, *name, *message_type, *desc));
    }

    let mut chunk_positions = Vec::new();
    for chunk in chunks {
        let header_position = FIRST_SECTION_OFFSET + body.len() as u64;
        let begin = chunk.iter().map(|m| m.1).min().unwrap_or(0);
        let end = chunk.iter().map(|m| m.1).max().unwrap_or(0);
        let mut header = Vec::new();
        uint_field(1, begin, &mut header);
        uint_field(2, end, &mut header);
        uint_field(3, chunk.len() as u64, &mut header);
        uint_field(4, chunk.iter().map(|m| m.2.len() as u64).sum(), &mut header);
        section(SECTION_CHUNK_HEADER, &header, &mut body);

        let body_position = FIRST_SECTION_OFFSET + body.len() as u64;
        let mut chunk_body = Vec::new();
        for (channel, time, data) in chunk {
            let mut message = Vec::new();
            string_field(1, channel, &mut message);
            uint_field(2, *time, &mut message);
            bytes_field(3, data, &mut message);
            bytes_field(1, &message, &mut chunk_body);
        }
        section(SECTION_CHUNK_BODY, &chunk_body, &mut body);
        chunk_positions.push((
            header_position,
            body_position,
            begin,
            end,
            chunk.len() as u64,
        ));
    }

    let index_position = FIRST_SECTION_OFFSET + body.len() as u64;
    let mut index = Vec::new();
    for (position, name, message_type, desc) in &channel_positions {
        let count = chunks
            .iter()
            .flatten()
            .filter(|(channel, _, _)| channel == name)
            .count() as u64;
        let mut cache = Vec::new();
        uint_field(1, count, &mut cache);
        string_field(2, name, &mut cache);
        string_field(3, message_type, &mut cache);
        bytes_field(4, desc, &mut cache);

        let mut entry = Vec::new();
        uint_field(1, u64::from(SECTION_CHANNEL), &mut entry);
        uint_field(2, *position, &mut entry);
        bytes_field(101, &cache, &mut entry);
        bytes_field(1, &entry, &mut index);
    }
    for (header_position, _body_position, begin, end, count) in &chunk_positions {
        let mut cache = Vec::new();
        uint_field(1, *count, &mut cache);
        uint_field(2, *begin, &mut cache);
        uint_field(3, *end, &mut cache);
        uint_field(4, 0, &mut cache);

        let mut entry = Vec::new();
        uint_field(1, u64::from(SECTION_CHUNK_HEADER), &mut entry);
        uint_field(2, *header_position, &mut entry);
        bytes_field(102, &cache, &mut entry);
        bytes_field(1, &entry, &mut index);
    }
    let mut index_section = Vec::new();
    section(SECTION_INDEX, &index, &mut index_section);

    let begin_time = chunks.iter().flatten().map(|m| m.1).min().unwrap_or(0);
    let end_time = chunks.iter().flatten().map(|m| m.1).max().unwrap_or(0);
    let message_count: u64 = chunks.iter().map(|chunk| chunk.len() as u64).sum();
    let total_size = FIRST_SECTION_OFFSET + body.len() as u64 + index_section.len() as u64;

    let mut header = Vec::new();
    uint_field(1, 1, &mut header);
    uint_field(2, 0, &mut header);
    uint_field(3, 0, &mut header);
    uint_field(4, 20_000_000_000, &mut header);
    uint_field(5, 60_000_000_000, &mut header);
    uint_field(6, index_position, &mut header);
    uint_field(7, chunks.len() as u64, &mut header);
    uint_field(8, channels.len() as u64, &mut header);
    uint_field(9, begin_time, &mut header);
    uint_field(10, end_time, &mut header);
    uint_field(11, message_count, &mut header);
    uint_field(12, total_size, &mut header);
    uint_field(13, 1, &mut header);

    let mut file = Vec::with_capacity(total_size as usize);
    section(SECTION_HEADER, &header, &mut file);
    file.resize(FIRST_SECTION_OFFSET as usize, 0);
    file.extend_from_slice(&body);
    file.extend_from_slice(&index_section);
    file
}

fn section(section_type: u32, payload: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&section_type.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&(payload.len() as i64).to_le_bytes());
    out.extend_from_slice(payload);
}

fn key(field: u32, wire: u8, out: &mut Vec<u8>) {
    varint(u64::from(field) << 3 | u64::from(wire), out);
}

fn bytes_field(field: u32, value: &[u8], out: &mut Vec<u8>) {
    key(field, 2, out);
    varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn string_field(field: u32, value: &str, out: &mut Vec<u8>) {
    bytes_field(field, value.as_bytes(), out);
}

fn uint_field(field: u32, value: u64, out: &mut Vec<u8>) {
    key(field, 0, out);
    varint(value, out);
}

fn fixed64_field(field: u32, value: f64, out: &mut Vec<u8>) {
    key(field, 1, out);
    out.extend_from_slice(&value.to_le_bytes());
}

fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}
