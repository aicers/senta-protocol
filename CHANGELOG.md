# Changelog

This file documents recent notable changes to this project. The format of this
file is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0](https://github.com/aicers/senta-protocol/releases/tag/0.1.0) - 2026-11-23

### Added

- *(auth)* add the active list, its lease, same-key replacement and standing-based admission ([#55](https://github.com/aicers/senta-protocol/pull/55))
- *(telemetry)* add the sender stream state machine that buffers, numbers, resends and resumes records ([#53](https://github.com/aicers/senta-protocol/pull/53))
- *(auth)* add the install configuration trust chain ([#52](https://github.com/aicers/senta-protocol/pull/52))
- *(telemetry)* add the receiver stream state machine ([#51](https://github.com/aicers/senta-protocol/pull/51))
- *(control)* add the control messages, status report send check and hardware identifier hash ([#50](https://github.com/aicers/senta-protocol/pull/50))
- *(telemetry)* add the Windows event log, journald and auditd bodies ([#49](https://github.com/aicers/senta-protocol/pull/49))
- *(telemetry)* add the Sysmon kind bodies, their Windows notation conversion and process keys ([#48](https://github.com/aicers/senta-protocol/pull/48))
- *(auth)* add the command state machine with replay protection, sequence floor and epoch reconciliation ([#47](https://github.com/aicers/senta-protocol/pull/47))
- *(auth)* add the document version state machine and Documents list intake ([#46](https://github.com/aicers/senta-protocol/pull/46))
- *(telemetry)* add the telemetry messages and the telemetry error enums ([#45](https://github.com/aicers/senta-protocol/pull/45))
- *(telemetry)* add the record format, record hash and kind registry ([#43](https://github.com/aicers/senta-protocol/pull/43))
- *(auth)* add the key set state machine, catch-up chains and enrollment result checks ([#44](https://github.com/aicers/senta-protocol/pull/44))
- *(auth)* add signed document schemas, per-typ verification and the validity window check ([#40](https://github.com/aicers/senta-protocol/pull/40))
- *(connection)* add shared framing, version handshake, keepalive and clock correction ([#34](https://github.com/aicers/senta-protocol/pull/34))
- add the shared result enums and their CBOR contract ([#32](https://github.com/aicers/senta-protocol/pull/32))
- *(auth)* add TLS helpers for endpoint identity and server verification ([#35](https://github.com/aicers/senta-protocol/pull/35))
- add the JWS verifier, strict content parsing and test signing helpers ([#33](https://github.com/aicers/senta-protocol/pull/33))
- add the senta-protocol crate with its feature flags ([#30](https://github.com/aicers/senta-protocol/pull/30))

### Fixed

- *(telemetry)* report re-dropped numbers and resend held copies on closed ([#63](https://github.com/aicers/senta-protocol/pull/63))
- *(connection)* reject maps that hold both a null key and an undefined key ([#42](https://github.com/aicers/senta-protocol/pull/42))
- *(auth)* reject second 60 and wide numbers in strict JSON ([#38](https://github.com/aicers/senta-protocol/pull/38))

### Other

- *(telemetry)* add a paired property test of the sender and receiver streams under mixed faults ([#61](https://github.com/aicers/senta-protocol/pull/61))
- add contract tests over in-memory TLS connections ([#60](https://github.com/aicers/senta-protocol/pull/60))
- add language-neutral test vectors for the trust contracts ([#59](https://github.com/aicers/senta-protocol/pull/59))
- *(telemetry)* cover collection moves before the buffer limit on reset ([#58](https://github.com/aicers/senta-protocol/pull/58))
- *(auth)* assert every diagnostic of the install id precedence case ([#57](https://github.com/aicers/senta-protocol/pull/57))
- *(auth)* correct what the crate signs and which PEM trust roots it rejects ([#39](https://github.com/aicers/senta-protocol/pull/39))
- update shared instruction blocks to 0.6.4 ([#5](https://github.com/aicers/senta-protocol/pull/5))
- add the Sysmon event manifest as the schema source ([#4](https://github.com/aicers/senta-protocol/pull/4))
- automate releases with release-plz ([#2](https://github.com/aicers/senta-protocol/pull/2))
- Add initial README, license and shared instructions
