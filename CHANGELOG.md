# Net Amikoj
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to 
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- An argument to allow `packet_sniffer.py` to specify the output directory.
- User can now interrupt packet scans in `packet_sniffer.py`.

### Fixed
- A broken link in this changefile.
- A bug that kept metadata files from being saved.

## [0.1.0] - 2019-10-12
### Added
- This changelog!
- A packet sniffer that saves sniffed packets in a PCAP file.
- PacketSniffer can save packet capture metadata in a JSON file. 
- Git ignore file that ignores PCAP files and flat tables (csv, excel, json).
- A project README.

[Unreleased]: https://github.com/brotherjack/macroy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/brotherjack/macroy/releases/tag/v0.1.0

