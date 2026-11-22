# Sysmon schemas

This directory holds the source that senta-protocol's Sysmon kinds and
their conversion rules are derived from. The files are third-party,
copied as published and never edited here, and they are **not** covered
by this repository's Apache-2.0 license; see [Licensing](#licensing).

- `sysmon/manifest.xml`: Microsoft's Sysmon event manifest from
  `SysmonCommon`, the single source of the Sysmon event definitions for
  both Windows and Linux.
- `sysmon/LICENSE`: the MIT license of `SysmonCommon`, kept with it.

The base schema version is 4.90, the one RFC 0014 in `aicers/taco` sets:
the `<manifest schemaversion="4.90" binaryversion="18">` entry of
`sysmon/manifest.xml`.

## Source

- Release: [microsoft/Sysmon-Linux 1.6.0][linux-release], the latest
  release, published 2026-11-06. The repository was formerly
  `microsoft/SysmonForLinux`, a name GitHub still redirects. Tag `1.6.0`
  is commit `962934f7e710a8e860ed5020f2068c6eba6aff64`.
- At that commit the submodule `sysmonCommon`
  (`https://github.com/Microsoft/SysmonCommon.git`) is pinned to
  [microsoft/SysmonCommon][sysmoncommon] commit
  `b6010a73e5145189687c83f94c8b5a23db7b8386` (committed 2026-04-23).
  `SysmonCommon` has no tags of its own.
- Original path: `manifest.xml` at the root of `SysmonCommon`, which is
  `sysmonCommon/manifest.xml` in `Sysmon-Linux`; git blob
  `60d96fa8c5c60f49a7f54a61c7e9898a02b60d64`.
- Copied verbatim from
  `https://raw.githubusercontent.com/microsoft/SysmonCommon/b6010a73e5145189687c83f94c8b5a23db7b8386/manifest.xml`.
- `sysmon/LICENSE` is `LICENSE` from the same `SysmonCommon` commit.

SHA-256:

- `sysmon/manifest.xml`:
  `ba814866289e01b72e8920fc7323cced384715fad93f27142f27e85a0dd70f45`
- `sysmon/LICENSE`:
  `076af159d9f100300ad0b5190cdbbc0d70714723c10a64a5e78e8b072850f6a3`

## Contents

The root element `<manifests>` holds 21 `<manifest>` entries, newest
first, from schema 4.90 down. Events and options carry a `target`
attribute: `all` for both platforms, `linux` for Linux only, or, for
options only, `internal`. Sysmon-Linux's `CMakeLists.txt` links this file
into the binary (`ld -r -b binary`) and generates its event headers and
message files from it through `manifest.tt`.

The 4.90 entry defines events 255 and 1 through 26 with `target="all"`,
and event 100, `SYSMONEVENT_EBPF_EVENT`, with `target="linux"`.

### Windows-only events 27 to 29

Windows Sysmon's schema 4.90 also defines events 27, 28 and 29
(`SYSMONEVENT_FILE_BLOCK_EXE`, `SYSMONEVENT_FILE_BLOCK_SHREDDING` and
`SYSMONEVENT_FILE_EXE_DETECTED`). They are not in this manifest, and none
of the Sysmon kinds in RFC 0014's Appendix A is one of them.

For events 255 and 1 through 26 the manifest matches Windows Sysmon. Its
4.90 entry was compared with the schema 4.90 text of Windows Sysmon
15.22, as `sysmon -s 4.90` prints it, by parsing both with Python's
`xml.etree.ElementTree` and setting the `target` attributes aside: each
of those events has the same attributes and the same `<data>` fields in
the same order.

### Why the Windows schema is not here

The Windows schema text is deliberately not committed. It is printed by
Windows Sysmon, which is distributed under the Sysinternals Software
License Terms, and those terms grant no explicit permission to
redistribute it. Every Sysmon kind in RFC 0014's Appendix A is in this
MIT-licensed manifest, so the Windows text is not needed.

## Licensing

`sysmon/manifest.xml` is MIT-licensed, Copyright (c) 2021 Windows
Sysinternals. The license text is in `sysmon/LICENSE`, as MIT requires.
`Sysmon-Linux` is MIT-licensed too.

[linux-release]: https://github.com/microsoft/Sysmon-Linux/releases/tag/1.6.0
[sysmoncommon]: https://github.com/microsoft/SysmonCommon
