# Changelog

## 0.1.0

- Initial release.
- Read Apollo Cyber RT `.record` headers, channels, chunk headers, chunk
  bodies, and indexes.
- Convert embedded `apollo.cyber.proto.ProtoDesc` descriptors to protobuf
  `FileDescriptorSet` schemas for Foxglove.
- Support complete, indexed recordings and incomplete recordings via a section
  scan.
- Register Foxglove channels with protobuf message encoding.
- Implement chunk-based seeking and backfill.
- Support opening multiple `.record` segments as one timeline.
- Add standalone Rust inspector and unit tests for the parser and descriptor
  conversion.
