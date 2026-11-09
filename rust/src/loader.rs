//! Foxglove data-loader adapter.
//!
//! This module is compiled only for WebAssembly. It turns the record index
//! into Foxglove channels and exposes chunk bodies as protobuf messages,
//! seeking directly to the next relevant chunk during playback.

use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Context, Result, anyhow};
use foxglove_data_loader::{
    BackfillArgs, DataLoader, DataLoaderArgs, Initialization, Message, MessageIterator,
    MessageIteratorArgs, Problem, reader,
};

use crate::descriptor::proto_desc_to_file_descriptor_set;
use crate::record::{self, ChunkInfo, RawMessage, RecordInfo};

const MESSAGE_ENCODING: &str = "protobuf";
const SCHEMA_ENCODING: &str = "protobuf";

struct ChannelDef {
    name: String,
    message_type: String,
    fds: Vec<u8>,
    has_descriptor: bool,
    message_count: u64,
}

pub struct CyberRecordLoader {
    paths: Vec<String>,
    files: Vec<RecordInfo>,
    channels: Vec<ChannelDef>,
}

impl CyberRecordLoader {
    fn merged_chunks(&self) -> Vec<MergedChunk> {
        let mut chunks = Vec::new();
        for (file_index, file) in self.files.iter().enumerate() {
            for chunk in &file.chunks {
                chunks.push(MergedChunk {
                    file_index,
                    chunk: chunk.clone(),
                });
            }
        }
        chunks.sort_by_key(|item| {
            (
                item.chunk.begin_time,
                item.chunk.end_time,
                item.file_index,
                item.chunk.body_offset,
            )
        });
        chunks
    }

    fn channel_maps(&self) -> (HashMap<u16, String>, HashMap<String, u16>) {
        let mut by_id = HashMap::with_capacity(self.channels.len());
        let mut by_name = HashMap::with_capacity(self.channels.len());
        for (index, channel) in self.channels.iter().enumerate() {
            let id = (index + 1) as u16;
            by_id.insert(id, channel.name.clone());
            by_name.insert(channel.name.clone(), id);
        }
        (by_id, by_name)
    }
}

impl DataLoader for CyberRecordLoader {
    type MessageIterator = CyberMessageIterator;
    type Error = anyhow::Error;

    fn new(args: DataLoaderArgs) -> Self {
        Self {
            paths: args.paths,
            files: Vec::new(),
            channels: Vec::new(),
        }
    }

    fn initialize(&mut self) -> Result<Initialization> {
        if self.paths.is_empty() {
            return Err(anyhow!("No files were provided to the Cyber record reader"));
        }

        let mut files = Vec::with_capacity(self.paths.len());
        let mut warnings: Vec<String> = Vec::new();

        for path in &self.paths {
            let mut input = reader::open(path);
            let info = record::read_record(&mut input)
                .with_context(|| format!("Failed to read Cyber record {path}"))?;
            for warning in &info.warnings {
                warnings.push(format!("{path}: {warning}"));
            }
            files.push(info);
        }

        // Merge channels across files by topic name. Apollo recordings are
        // usually split into `.record.00000`, `.record.00001`, ... segments;
        // treating their channels as one logical topic gives Foxglove a single
        // timeline for the whole recording.
        let mut merged: BTreeMap<String, ChannelDef> = BTreeMap::new();
        let mut schema_conflicts = 0usize;
        for file in &files {
            for channel in &file.channels {
                if channel.name.is_empty() {
                    continue;
                }
                if let Some(existing) = merged.get_mut(&channel.name) {
                    existing.message_count =
                        existing.message_count.saturating_add(channel.message_count);
                    if !channel.message_type.is_empty()
                        && !existing.message_type.is_empty()
                        && channel.message_type != existing.message_type
                    {
                        schema_conflicts += 1;
                    }
                    if existing.message_type.is_empty() {
                        existing.message_type = channel.message_type.clone();
                    }
                    if existing.fds.is_empty() && !channel.proto_desc.is_empty() {
                        existing.fds = proto_desc_to_file_descriptor_set(&channel.proto_desc);
                        existing.has_descriptor = !existing.fds.is_empty();
                    }
                } else {
                    let fds = proto_desc_to_file_descriptor_set(&channel.proto_desc);
                    merged.insert(
                        channel.name.clone(),
                        ChannelDef {
                            name: channel.name.clone(),
                            message_type: channel.message_type.clone(),
                            has_descriptor: !fds.is_empty(),
                            fds,
                            message_count: channel.message_count,
                        },
                    );
                }
            }
        }

        if merged.len() > usize::from(u16::MAX) {
            return Err(anyhow!(
                "Record contains {} topics, but the Foxglove data-loader API supports at most {}",
                merged.len(),
                u16::MAX
            ));
        }

        if schema_conflicts > 0 {
            warnings.push(format!(
                "{schema_conflicts} channel(s) appeared with differing schemas across files; using the first schema"
            ));
        }

        let channels: Vec<ChannelDef> = merged.into_values().collect();
        let without_descriptor = channels
            .iter()
            .filter(|channel| !channel.has_descriptor)
            .count();
        if without_descriptor > 0 {
            warnings.push(format!(
                "{without_descriptor} channel(s) do not contain a usable protobuf descriptor; their raw bytes will still be available, but Foxglove may not decode them"
            ));
        }
        if channels.is_empty() {
            warnings.push("No channels were found in the recording".to_string());
        }

        let start_time = files.iter().map(RecordInfo::start_time).min().unwrap_or(0);
        let end_time = files.iter().map(RecordInfo::end_time).max().unwrap_or(0);
        if end_time < start_time {
            warnings.push(format!(
                "Record end time {end_time} is before start time {start_time}"
            ));
        }

        let mut builder = Initialization::builder()
            .start_time(start_time)
            .end_time(end_time);

        for (index, channel) in channels.iter().enumerate() {
            let channel_id = (index + 1) as u16;
            if channel.has_descriptor && !channel.message_type.is_empty() {
                let schema = foxglove::Schema::new(
                    channel.message_type.clone(),
                    SCHEMA_ENCODING,
                    channel.fds.clone(),
                );
                let linked_schema = builder
                    .add_schema(schema)
                    .message_encoding(MESSAGE_ENCODING);
                let linked_channel = linked_schema
                    .add_channel_with_id(channel_id, &channel.name)
                    .ok_or_else(|| anyhow!("Duplicate Foxglove channel id {channel_id}"))?;
                linked_channel.message_count(channel.message_count);
            } else {
                let linked_channel = builder
                    .add_channel_with_id(channel_id, &channel.name)
                    .ok_or_else(|| anyhow!("Duplicate Foxglove channel id {channel_id}"))?;
                linked_channel
                    .message_encoding(MESSAGE_ENCODING)
                    .message_count(channel.message_count);
            }
        }

        for warning in warnings {
            builder = builder.add_problem(Problem::warn(warning));
        }

        self.files = files;
        self.channels = channels;
        Ok(builder.build())
    }

    fn create_iter(&mut self, args: MessageIteratorArgs) -> Result<Self::MessageIterator> {
        let chunks = self.merged_chunks();
        let start_time = args.start_time.unwrap_or(0);
        let end_time = args.end_time.unwrap_or(u64::MAX);
        let first_chunk = chunks.partition_point(|chunk| chunk.chunk.end_time < start_time);

        let requested: HashSet<u16> = args.channels.into_iter().collect();
        let (_, ids_by_name) = self.channel_maps();

        Ok(CyberMessageIterator {
            paths: self.paths.clone(),
            chunks,
            next_chunk: first_chunk,
            current_messages: Vec::new().into_iter(),
            start_time,
            end_time,
            requested,
            ids_by_name,
            readers: (0..self.paths.len()).map(|_| None).collect(),
            finished: false,
        })
    }

    fn get_backfill(&mut self, args: BackfillArgs) -> Result<Vec<Message>> {
        let (names_by_id, ids_by_name) = self.channel_maps();
        let wanted: HashMap<u16, String> = args
            .channels
            .iter()
            .filter_map(|id| names_by_id.get(id).map(|name| (*id, name.clone())))
            .collect();
        if wanted.is_empty() {
            return Ok(Vec::new());
        }

        let chunks = self.merged_chunks();
        let mut next = chunks.partition_point(|chunk| chunk.chunk.begin_time <= args.time);
        let mut best: HashMap<u16, (u64, Vec<u8>)> = HashMap::new();
        let mut readers: Vec<Option<reader::Reader>> =
            (0..self.paths.len()).map(|_| None).collect();

        while next > 0 && best.len() < wanted.len() {
            next -= 1;
            let chunk = &chunks[next];
            // A chunk may contain messages earlier than its begin time only in
            // malformed files; reading it is still safe and cheap enough here.
            let input = open_reader(&mut readers, &self.paths, chunk.file_index)?;
            let messages = record::read_chunk(input, &chunk.chunk).with_context(|| {
                format!("Failed to read chunk at byte {}", chunk.chunk.body_offset)
            })?;

            for message in messages {
                if message.time > args.time {
                    continue;
                }
                let Some(id) = ids_by_name.get(&message.channel_name).copied() else {
                    continue;
                };
                if !wanted.contains_key(&id) {
                    continue;
                }
                match best.get_mut(&id) {
                    Some((time, _)) if message.time <= *time => {}
                    Some(slot) => *slot = (message.time, message.data),
                    None => {
                        best.insert(id, (message.time, message.data));
                    }
                }
            }
        }

        let mut backfill: Vec<Message> = best
            .into_iter()
            .map(|(channel_id, (time, data))| Message {
                channel_id,
                log_time: time,
                publish_time: time,
                data,
            })
            .collect();
        backfill.sort_by_key(|message| message.channel_id);
        Ok(backfill)
    }
}

#[derive(Clone)]
struct MergedChunk {
    file_index: usize,
    chunk: ChunkInfo,
}

pub struct CyberMessageIterator {
    paths: Vec<String>,
    chunks: Vec<MergedChunk>,
    next_chunk: usize,
    current_messages: std::vec::IntoIter<RawMessage>,
    start_time: u64,
    end_time: u64,
    requested: HashSet<u16>,
    ids_by_name: HashMap<String, u16>,
    readers: Vec<Option<reader::Reader>>,
    finished: bool,
}

impl MessageIterator for CyberMessageIterator {
    type Error = anyhow::Error;

    fn next(&mut self) -> Option<Result<Message>> {
        if self.finished || self.requested.is_empty() {
            return None;
        }

        loop {
            if let Some(raw) = self.current_messages.next() {
                let Some(channel_id) = self.ids_by_name.get(&raw.channel_name).copied() else {
                    continue;
                };
                if !self.requested.contains(&channel_id) {
                    continue;
                }
                if raw.time < self.start_time {
                    continue;
                }
                if raw.time > self.end_time {
                    // Messages inside a chunk are normally time-ordered. If a
                    // malformed file is not, the next chunk's begin_time check
                    // still stops playback once the requested range is over.
                    continue;
                }
                return Some(Ok(Message {
                    channel_id,
                    log_time: raw.time,
                    publish_time: raw.time,
                    data: raw.data,
                }));
            }

            if self.next_chunk >= self.chunks.len() {
                self.finished = true;
                return None;
            }

            let chunk = self.chunks[self.next_chunk].clone();
            self.next_chunk += 1;

            if chunk.chunk.end_time < self.start_time {
                continue;
            }
            if chunk.chunk.begin_time > self.end_time {
                self.finished = true;
                return None;
            }

            let input = match open_reader(&mut self.readers, &self.paths, chunk.file_index) {
                Ok(input) => input,
                Err(error) => {
                    self.finished = true;
                    return Some(Err(error));
                }
            };
            match record::read_chunk(input, &chunk.chunk) {
                Ok(messages) => {
                    self.current_messages = messages.into_iter();
                }
                Err(error) => {
                    self.finished = true;
                    return Some(Err(anyhow!(
                        "Failed to read chunk at byte {}: {error}",
                        chunk.chunk.body_offset
                    )));
                }
            }
        }
    }
}

fn open_reader<'a>(
    readers: &'a mut [Option<reader::Reader>],
    paths: &[String],
    index: usize,
) -> Result<&'a mut reader::Reader> {
    if readers[index].is_none() {
        readers[index] = Some(reader::open(&paths[index]));
    }
    readers[index]
        .as_mut()
        .ok_or_else(|| anyhow!("Could not open {}", paths[index]))
}
