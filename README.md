# Apollo Cyber Record for Foxglove

A [Foxglove](https://foxglove.dev) data-loader extension for Apollo Cyber RT
`.record` files. Open a recording and browse every channel on the normal
Foxglove timeline - no Apollo installation, ROS bridge, or conversion step.

The extension contains a from-scratch Rust reader for the Cyber record
container. Apollo's protobuf descriptors are converted from
`apollo.cyber.proto.ProtoDesc` into standard `FileDescriptorSet` schemas, so
Foxglove can decode messages with its built-in protobuf support.

## Features

- Opens uncompressed Apollo Cyber RT `.record` files directly in Foxglove.
- Recovers channel schemas from the descriptors embedded in the recording.
- Supports complete recordings with an index and interrupted recordings
  without one (the reader falls back to a section scan).
- Seeks by chunk, and implements backfill so panels are populated after a seek.
- Merges multiple `.record` segments into one timeline when opened together.
- Ships as a single `.foxe` file with the parser compiled to WebAssembly.
- The parser is also usable as a small standalone Rust crate.

## Install

### From a release

1. Download the latest `*.foxe` file from
   [Releases](https://github.com/XiaoJiaoYaZi/foxglove-cyber_record-extension/releases).
2. In Foxglove Desktop, open **Settings -> Extensions** and install the file.
3. Open a `.record` file with **File -> Open**.

Installing extensions from the public registry is supported in Foxglove
Desktop. A developer seat may be required for local extension development.

### Build from source

Requirements:

- Node.js 18+ and npm
- Rust (stable) with the WebAssembly target:

```sh
rustup target add wasm32-unknown-unknown
```

Then:

```sh
npm install
npm run package
```

This produces `xiaojiaoyazi.foxglove-cyberrecord-<version>.foxe` in the project
root. Install it from Foxglove's extension settings.

For iterative development:

```sh
npm run build
npm run local-install
```

## Usage notes

### File names

The data loader is registered for the `.record` extension. Apollo's segmented
recordings are often named like:

```text
demo.00000.20240101123000
demo.00001.20240101123100
```

Rename the segments to `.record` files (for example `demo-0.record`,
`demo-1.record`) and open them together. Multi-file loading is enabled and the
segments are merged into one timeline.

### Supported records

- Cyber record major version 1 (the current format) is supported.
- Uncompressed chunks (`COMPRESS_NONE`) are supported. The default
  `cyber_recorder` configuration uses uncompressed chunks. A recording whose
  header declares BZ2/LZ4 compression is opened, but its compressed chunks
  cannot be decoded; the extension reports a problem in Foxglove's Problems
  panel.
- A truncated or still-being-written record is readable up to the last complete
  section. Channels and messages from the valid prefix are exposed.

### Missing schemas

If a channel has no embedded descriptor, or the descriptor is not parseable,
the channel is still registered with `protobuf` encoding so its raw bytes are
available. Foxglove may not be able to render typed panels for that channel. A
warning is shown in the Problems panel.

## How it works

A Cyber record is a sequence of length-delimited sections. Each section starts
with a 16-byte C++ `struct Section` header:

```text
u32 section_type
u32 padding
i64 payload_size
<protobuf payload>
```

The first section is a `Header` protobuf, padded so the next section begins at
byte `16 + 2048 = 2064`. Subsequent sections are channels, chunk headers, chunk
bodies, and (for completed files) an index. The reader uses the index when it is
available and otherwise scans sections, counting messages per channel.

Channel schema bytes in a Cyber record are an `apollo.cyber.proto.ProtoDesc`:
a serialized `FileDescriptorProto` plus recursive dependencies. Foxglove wants
a standard `google.protobuf.FileDescriptorSet`, so the reader unwraps the
recursive tree and emits a descriptor set with dependencies first.

## Rust SDK

The parser lives in [`rust/src/record.rs`](rust/src/record.rs) and has no
Foxglove dependency, which makes it usable outside the extension:

```rust
use std::fs::File;
use cyberrecord::record::{read_chunk, read_record};

let mut file = File::open("recording.record")?;
let info = read_record(&mut file)?;
println!("{} channels, {} chunks", info.channels.len(), info.chunks.len());

for message in read_chunk(&mut file, &info.chunks[0])? {
    println!("{} @ {}", message.channel_name, message.time);
}
```

Try the included sample recording in Foxglove, or inspect it from the command
line:

```sh
cargo run --manifest-path rust/Cargo.toml --example inspect -- test-data/demo.record
```

Run the tests:

```sh
cargo test --manifest-path rust/Cargo.toml
```

## Compatibility and limitations

- The data-loader API is marked experimental by Foxglove; this project pins
  `foxglove_data_loader` 0.2.x and `@foxglove/extension` 3.5.x.
- Protobuf payloads are passed through unchanged. Any protobuf type present in
  the recording's descriptor set can be decoded by Foxglove.
- Compression types other than `COMPRESS_NONE` are not decompressed.
- This is not an official Apollo or Foxglove project.

## Publishing

### Package

```sh
npm run package
```

Record the SHA-256 of the exact file you upload. The registry entry must match
that release asset:

```sh
sha256sum xiaojiaoyazi.foxglove-cyberrecord-0.1.0.foxe
```

### Share with an organization

```sh
foxglove extensions publish ./xiaojiaoyazi.foxglove-cyberrecord-0.1.0.foxe
```

See the [Foxglove publishing guide](https://docs.foxglove.dev/docs/extensions/publish)
and the [Foxglove CLI](https://github.com/foxglove/foxglove-cli).

### Publish publicly

1. Push this repository to GitHub at the URL in `homepage`. If you use a
   different account or organization, update `publisher` and `homepage` in
   `package.json` and rebuild before tagging.
2. The extension ID is `<publisher>.<name>`, currently
   `xiaojiaoyazi.foxglove-cyberrecord`.
3. Create a release tag, for example `v0.1.0`, and attach the `.foxe`.
4. Add an entry to
   [`foxglove/extension-registry`](https://github.com/foxglove/extension-registry)
   using the format in [`registry/extension-entry.json`](registry/extension-entry.json),
   update its SHA-256 and release URL, and open a pull request.
5. After the registry PR is merged, the extension is discoverable in Foxglove
   Desktop's extension browser.

The release workflow in
[`.github/workflows/release.yml`](.github/workflows/release.yml) builds and
attaches the `.foxe` automatically when a `v*` tag is pushed.

## Development

```sh
npm test                 # cargo tests
npm run check:wasm       # wasm type-check
npm run build            # wasm + extension bundle
npm run package          # .foxe artifact
```

Project layout:

```text
src/index.ts             Foxglove extension entry point
rust/src/record.rs       Cyber record container/protobuf reader
rust/src/descriptor.rs   ProtoDesc -> FileDescriptorSet conversion
rust/src/loader.rs       Foxglove DataLoader / MessageIterator adapter
rust/examples/inspect.rs Standalone record inspector
```

## License

Apache-2.0. The Cyber record format was implemented from the publicly
documented Apollo Cyber RT format; see [`NOTICE`](NOTICE).
