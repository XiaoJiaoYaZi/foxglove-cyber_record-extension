//! Print a summary of a Cyber record.
//!
//! ```sh
//! cargo run --example inspect -- path/to/recording.record
//! ```

use std::env;
use std::fs::File;

use cyberrecord::descriptor::proto_desc_to_file_descriptor_set;
use cyberrecord::record::{read_chunk, read_record};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: inspect <recording.record>")?;
    let mut file = File::open(&path)?;
    let info = read_record(&mut file)?;

    println!("file: {path}");
    println!(
        "version: {}.{}",
        info.header.major_version, info.header.minor_version
    );
    println!("complete: {}", info.header.is_complete);
    println!(
        "time: {} .. {} ({} ns)",
        info.start_time(),
        info.end_time(),
        info.end_time().saturating_sub(info.start_time())
    );
    println!("channels: {}", info.channels.len());
    println!("chunks: {}", info.chunks.len());
    println!("messages: {}", info.message_count());

    for channel in &info.channels {
        let fds = proto_desc_to_file_descriptor_set(&channel.proto_desc);
        println!(
            "  {:32} {:40} {:8} messages, descriptor: {} bytes",
            channel.name,
            channel.message_type,
            channel.message_count,
            fds.len()
        );
    }

    for warning in &info.warnings {
        println!("warning: {warning}");
    }

    if let Some(chunk) = info.chunks.first() {
        let messages = read_chunk(&mut file, chunk)?;
        println!("first chunk: {} messages", messages.len());
        for message in messages.iter().take(3) {
            println!(
                "  {} @ {} ({} bytes)",
                message.channel_name,
                message.time,
                message.data.len()
            );
        }
    }

    Ok(())
}
