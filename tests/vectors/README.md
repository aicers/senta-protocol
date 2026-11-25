# Test vectors

The files here are language-neutral test vectors for the trust contracts
of this crate: JWS verification, the install configuration trust chain,
the key set, document version and command state machines, enrollment
results and the hardware identifier hash; and for the CBOR encoding of
two control messages and of the active list's updates. A signer, a
verifier, an encoder or a decoder written in another language reads them
to check that it follows the same rules as the crate: it builds the same
bytes from the same inputs, and reaches the same result for each case.

Everything a reader needs is in the JSON files and this README; nothing
requires reading Rust.

## Versions

- The vectors are pinned per crate release. A user takes the
  `tests/vectors/` directory of the tag of the crate version it targets.
  Tags are made by release-plz and have no `v` prefix: `X.Y.Z`.
- The bytes of a released version's vector files never change within
  that version. A change to the vectors goes into the next version.
- The first version that pins the vectors is the crate's first
  release. The vectors on `main` before the first release, and between
  releases, are not pinned: they may change at any commit.
- Neither the vector files nor this README name a crate version, so that
  the version bump of a release does not make the committed files differ
  from the generator's output.
- Every file carries `format_version`, an integer, now `1`. It is raised
  when the format changes: the meaning of a field, or the structure of a
  file. Adding cases, or changing values within the same format, leaves
  it as it is.

## Files

Each file holds one category, named by the file name without `.json`:

| File | Category |
| --- | --- |
| `jws.json` | JWS verification of the eleven `typ`s |
| `trust_chain.json` | install configuration trust chain |
| `keyset.json` | key set rotation, recovery and catch-up |
| `leak.json` | a leaked customer key, before and after recovery |
| `document_versions.json` | document version state machine |
| `enroll_result.json` | enrollment result checks |
| `commands.json` | command state machine targets |
| `hardware_hash.json` | hardware identifier hash |
| `control_cbor.json` | CBOR of `EnrollRequest` and `StatusReport` |
| `active_list.json` | CBOR of the active list's updates |

There are no subdirectories, and no file here other than the JSON
vector files and this README.

## Regenerating

The files are the output of a generator, in
`tests/test_vectors/` of this repository. To write them again:

```sh
cargo test --no-default-features --features auth,control,test-util \
  --test test_vectors -- --ignored regenerate_vectors
```

The tests of the same target fail when a committed JSON vector file
differs in any byte from the generator's output, when the generator
produces a file that is not committed, and when a JSON vector file is
committed that the generator does not produce. This README is not
compared. They also run every case through the crate and compare its
results with the expected ones, and fail when a case name repeats within
a file.

The generator writes each file as JSON indented by two spaces, with the
members of each object in a fixed order, ending in one newline. Nothing
in the output is random: every key comes from a fixed seed, and every
UUID and time is fixed, so generating again gives the same bytes.

## Notation

- Field names are snake_case.
- Bytes are unpadded base64url (RFC 4648 section 5, no `=`), except in
  `control_cbor.json` and `active_list.json`, which write bytes in
  standard base64 (see their section).
- Times are RFC 3339 UTC strings, such as `2026-01-02T00:00:00Z`.
- UUIDs are lowercase hyphenated strings.
- Versions, sequence numbers (`seq`) and recovery epochs are JSON
  integers.
- A field marked optional below is left out when it has no value; it is
  never written as `null` unless this README says that `null` means
  something.

## The top level of a file

Every file is one JSON object with these members, in this order:

- `format_version`: the format version, an integer (see Versions).
- `category`: the file's category, as in the table above.
- `keys`: the keys the file's documents use; an empty list in
  `hardware_hash.json`, `control_cbor.json` and `active_list.json`,
  which use none.
- `cases`: the cases. Each has a `name`, unique within the file, and a
  `description` for people to read.

### Keys

Each entry of `keys` has:

- `kid`: the key's kid, as JWS headers carry it.
- `kind`: the kind of key: `vendor`, `install_signing`, `customer` or
  `recovery`. `vendor-other-1` is listed as a `vendor` key: it is meant
  as one, though its kid follows neither vendor prefix.
- `seed`: the 32-byte Ed25519 seed (the RFC 8032 private key).
- `jwk`: the public key, `{"kty":"OKP","crv":"Ed25519","x":…}`.

**The seeds are for tests only and are not secret.** No key here signs
anything outside these vectors.

## Results

Three result enums of the crate are written in the shape their CBOR
form has:

- `DocumentResult`, what receiving a signed document comes to;
- `CommandResultKind`, what a command comes to;
- `InstallConfigFailure`, why an install configuration failed.

A variant without content is its tag as a string: `"bad_signature"`. A
variant with content is an object of exactly one member, the tag mapped
to the content: `{"keyset_gap": {"have_epoch": 1, "have_version": 3}}`,
or `{"rejected": "wrong_target"}` for a `CommandResultKind` holding a
`DocumentResult`.

The other results are written as below. None of their outer tags is a
tag of the three enums, nor of one another. The `<why>` of a failed
enrollment is read only inside `enroll_failed`: its `rejected` there
holds a `DocumentResult` and is not a `CommandResultKind`.

- A JWS that verified:
  `{"verified": {"payload_sha256": <bytes>}}`.
- An install configuration whose trust chain verified, with the trust
  state it gives:
  `{"installed": {"recovery_epoch": …, "keyset_version": …,
  "recovery_key_version": …}}`.
- An install configuration whose trust chain failed:
  `{"install_failed": {"failure": <InstallConfigFailure>, "step": <n>,
  "document": <typ>}}`. `document` is the `typ` of the document the
  failure is about. `step` is the step that failed:
  1. reading the install configuration before its signature is verified;
  2. the deployment certificate against the vendor keys;
  3. the install configuration against the deployment certificate's
     install signing key, and its `install_id`;
  4. the key set against its own `current_kid`, and its customer ids;
  5. the address document and the enrollment token against the key set.
- An enrollment that succeeded: `{"enrolled": <endpoint_id>}`.
- An enrollment that failed: `{"enroll_failed": <why>}`, where `<why>`
  is `"spki_mismatch"`, `"attempt_id_mismatch"`, `"token_id_mismatch"`
  or `"recovery_epoch_mismatch"` for the comparison with the attempt
  that failed; `{"rejected": <DocumentResult>}` when the enrollment
  result did not verify; or `{"chain": {"index": <n>, "result":
  <DocumentResult>}}` when the chain stopped at its document `n`.
- A command accepted to run: `"execute"`.
- A step that has no result of its own and completed: `"ok"`.
- A document of a list that was not processed, because a key document
  before it stopped the chain: `"not_processed"`.

## `jws.json`

Each case verifies one JWS as a document of one `typ`.

- `signed_by` (optional): the kid whose key signed the JWS. It is
  present exactly when the signature is that key's genuine signature of
  the signing input `<header segment>.<payload segment>`; in the
  `json_serialization` cases the segments are the `protected` and
  `payload` members, and the signature is the `signature` member.
- `input.jws`: the text handed to the verifier, as it is. It is a
  compact JWS, except in the `json_serialization` cases, where it is the
  flattened JWS JSON serialization of a valid document.
- `input.header_json`, `input.payload_json` (optional): the header and
  the payload, base64url-decoded, as JSON strings, present when the
  bytes are UTF-8. They are for reading only. They are not rewritten as
  nested JSON, so a repeated key or a number such as 2^53 stays as it
  was signed.
- `input.expected_typ`: the `typ` the document is verified as.
- `input.trusted_keys`: the keys the verifier's key source holds, each a
  `kid` of the key list and the `kind` it is registered as. The key
  source finds a key only under exactly its kid.
- `input.revoked_kids`: kids the key source reports as revoked. Any kid
  in neither list is unknown.
- `expected`: `{"verified": …}`, or the `DocumentResult` of the failure.

The `payload_sha256` of a valid case is the SHA-256 of the payload
segment base64url-decoded: the exact bytes signed, never the JSON of
`payload_json` serialized again.

### Signing

Every JWS with a `signed_by` is reproducible byte for byte: take
the header and payload bytes (`header_json` and `payload_json` as UTF-8),
base64url-encode each, join them with `.`, sign that ASCII string with
the Ed25519 seed of `signed_by` (Ed25519 is deterministic), and append
`.` and the base64url signature. The headers of ordinary documents are
`{"alg":"EdDSA","typ":<typ>,"kid":<kid>}` with no whitespace. A
`json_serialization` case is the same three base64url strings as the
`protected`, `payload` and `signature` members of one JSON object.

### Cases

Each of the eleven `typ`s has these cases, named `<typ>:<case>`:

| Case | Expected |
| --- | --- |
| `valid` | `verified`, with the payload hash |
| `alg_not_eddsa`: `alg` is `ES256` | `schema_error` |
| `typ_mismatch`: header `typ` of another `typ` | `schema_error` |
| `crit_header`: header has `crit` | `schema_error` |
| `unknown_header_member`: `extra` | `schema_error` |
| `unknown_content_field` | `schema_error` |
| `missing_content_field` | `schema_error` |
| `duplicate_content_key` | `schema_error` |
| `integer_2_pow_53` | `schema_error` |
| `signature_bit_flipped` | `bad_signature` |
| `json_serialization` | `schema_error` |
| `wrong_key_class` | `wrong_key_class` |

`signature_bit_flipped` flips the lowest bit of the first signature
byte of the `valid` case. `wrong_key_class` is signed by a key of a
kind the `typ` does not allow.

`integer_2_pow_53` sets an integer field to 2^53, one above the largest
integer a content accepts. The field is `recovery_key_version` for
`senta-install-config` and `senta-recovery-key`, `keyset_version` for
`senta-keyset`, `recovery_epoch` for `senta-enroll-result`, `version`
for `senta-policy`, `senta-assign`, `senta-addresses` and
`senta-update`, and `seq` for `senta-command`. `senta-deployment-cert`
and `senta-enroll` have no such case: their contents have no integer
field, and a number added to them would be an unknown field instead.

### The fields of `senta-policy` and `senta-update`

The `valid` `senta-policy` has a `sysmon_configs` entry for `windows`
and one for `linux`, `existing_sysmon` `keep`, and a
`windows_sysmon_package`. The `valid` `senta-update` is for a group, and
has `packages` for three platforms: `windows-x86_64-msi`,
`linux-x86_64-deb` and `linux-x86_64-rpm`.

The payload of every case of these two `typ`s that verifies writes its
members in the order the crate serializes the content, so a signer in
another language that writes the same content in that order signs the
same bytes. The order is:

- `senta-policy`: `recovery_epoch`, `group_id`, `version`,
  `collection_mode`, `sysmon_configs`, `existing_sysmon`,
  `windows_sysmon_package` (left out when there is none),
  `field_exclusions`, `audit_settings`, `event_log_channels`,
  `status_ui`.
- an entry of `sysmon_configs`: `os`, `sha256`, `sources`.
- `windows_sysmon_package`: `version`, `sha256`, `size`, `sources`.
- `senta-update`: `recovery_epoch`, `version`, `group_id` or
  `endpoint_id`, `target_version`, `packages` (left out when
  `target_version` is `null`), `rollback`, `issued_at`, `expires_at`.
- an entry of `packages`: `platform`, `sha256`, `size`, `sources`.

Besides the cases above, these two `typ`s have the cases below, each a
change of the `valid` content signed by the same key. Every case named
`valid_…` is `verified`, with its payload hash; every other one is
`schema_error`.

`senta-policy`:

- `valid_without_windows_sysmon_package`: leaves out
  `windows_sysmon_package`.
- `valid_empty_sysmon_configs`: `sysmon_configs` is `[]`.
- `valid_unknown_os`: a `sysmon_configs` entry has the `os` `macos`.
- `valid_existing_sysmon_take_over`: `existing_sysmon` is `take_over`.
- `sysmon_configs_repeated_os`: two `sysmon_configs` entries have the
  `os` `windows`.
- `sysmon_configs_empty_os`: a `sysmon_configs` entry has the `os` `""`.
- `sysmon_configs_empty_sources`: a `sysmon_configs` entry has the
  `sources` `[]`.
- `sysmon_configs_unknown_field`: a `sysmon_configs` entry has an
  unknown field.
- `existing_sysmon_missing`: leaves out `existing_sysmon`.
- `existing_sysmon_unknown`: `existing_sysmon` is `replace`.
- `windows_sysmon_package_null`: `windows_sysmon_package` is `null`.
- `windows_sysmon_package_empty_version`: its `version` is `""`.
- `windows_sysmon_package_sha256_31_bytes`: its `sha256` is 31 bytes.
- `windows_sysmon_package_size_0`: its `size` is `0`.
- `windows_sysmon_package_empty_sources`: its `sources` is `[]`.
- `windows_sysmon_package_unknown_field`: it has an unknown field.
- `sysmon_config_present`: also has `sysmon_config`, the field
  `sysmon_configs` replaced.

`senta-update`:

- `valid_null_target_version`: an update of an endpoint whose
  `target_version` is `null`, without `packages`.
- `valid_one_platform`: `packages` has the `windows-x86_64-msi` entry
  alone.
- `valid_unknown_platform`: `packages` has an entry for
  `macos-aarch64-pkg`.
- `packages_missing`: leaves out `packages`.
- `packages_empty`: `packages` is `[]`.
- `packages_repeated_platform`: two `packages` entries have the
  `platform` `windows-x86_64-msi`.
- `packages_empty_platform`: a `packages` entry has the `platform` `""`.
- `packages_empty_sources`: a `packages` entry has the `sources` `[]`.
- `packages_size_0`: a `packages` entry has the `size` `0`.
- `packages_sha256_33_bytes`: a `packages` entry has a `sha256` of 33
  bytes.
- `packages_unknown_field`: a `packages` entry has an unknown field.
- `null_target_version_with_packages`: the `valid_null_target_version`
  content with `packages`.
- `package_sha256_present`: also has `package_sha256`, a field
  `packages` replaced.
- `package_size_present`: also has `package_size`, a field `packages`
  replaced.
- `sources_present`: also has a top-level `sources`, a field `packages`
  replaced.

## `control_cbor.json` and `active_list.json`

These two files hold CBOR encodings, not signed documents.
`control_cbor.json` holds bodies of two control messages the endpoint
sends, `EnrollRequest` and `StatusReport`; `active_list.json` holds
updates of the active list, `ListUpdate`. Each case is one value written
twice: as its CBOR bytes, and as a JSON view of the same value. A
decoder decodes `cbor` and compares what it gets with `value`; an
encoder encodes the value `value` shows and compares its bytes with
`cbor`.

Each case has:

- `name`: `<type>:<case>`, where `<type>` is `enroll_request` or
  `status_report` in `control_cbor.json`, and `list_update` in
  `active_list.json`.
- `description`: for people to read.
- `type` (`control_cbor.json` only): `enroll_request` or
  `status_report`, the message the bytes are the body of.
- `value`: the JSON view of the value (below).
- `cbor`: the CBOR bytes, in **standard base64 with padding** (RFC 4648
  section 4: the alphabet with `+` and `/`, padded with `=`). This is not
  the unpadded base64url the other files use.

The bytes of a `control_cbor.json` case are the message body alone, the
`b` of the envelope `[t, b]`: neither the envelope nor the frame. The
bytes of an `active_list.json` case are the whole update.

Every map and array in the bytes has a definite length, every integer is
in its shortest form, every map's keys are text strings in the order the
JSON view lists them, and an optional field without a value is left out,
never written as null. An encoder that follows these rules and the view
writes exactly `cbor`.

### The JSON view

The view follows the CBOR value:

- a map is an object with the same keys in the same order;
- an array is an array;
- a text string is a string, an integer a number (negative where the
  CBOR integer is), and `true` and `false` themselves;
- an enum is written as its CBOR form is: a variant without content is
  its tag, a string (`"tpm"`), and one with content an object of one
  member, the tag mapped to the content (`{"suspended": {"reason":
  "revoked"}}`). A tag the crate does not know is kept as it is, so the
  view shows it as any other tag.

The fields below are where the view differs from that rule. A UUID,
which CBOR writes as a byte string of its 16 bytes, is the lowercase
hyphenated string. A point in time, which CBOR writes as an integer
count of nanoseconds since the Unix epoch, is an RFC 3339 UTC string
ending in `Z`, with a fraction of a second only when it has one and no
trailing zero: `2026-01-02T00:00:00Z`, `2026-01-01T23:58:29.876543211Z`.
Any other byte string is standard base64 with padding, as `cbor` is.
`[]` stands for every element of a list:

- `EnrollRequest`:
  - UUIDs: `attempt_id`.
  - Times: none.
  - Other byte strings: `hardware.machine_id_hash`.
- `StatusReport`:
  - UUIDs: `documents[].target.group`, `documents[].target.endpoint`,
    `documents[].target.customer`, `transport.entries[].entry_id`.
  - Times: `transport.entries[].last_success_at`,
    `clock.offset.measured_at`.
  - Other byte strings: `hardware.machine_id_hash`.
- `ListUpdate`:
  - UUIDs: `full.entries[].endpoint_id`,
    `full.entries[].customer_endpoint_id`,
    `diff.upserts[].endpoint_id`, `diff.upserts[].customer_endpoint_id`,
    `diff.removals[]`.
  - Times: none.
  - Other byte strings: `full.entries[].spki_sha256`,
    `diff.upserts[].spki_sha256`.

Every other string of a view is a CBOR text string, and every number a
CBOR integer. The `enroll_token` of an `EnrollRequest` is a fixed test
value in the form of a compact JWS; nothing verifies it.

### Cases

`control_cbor.json`:

- `enroll_request:with_smbios`: a Windows endpoint's request whose
  hardware has `smbios_uuid` and `smbios_serial`.
- `enroll_request:without_smbios`: a Linux endpoint's request in VDI
  mode whose hardware has neither.
- `status_report:optional_fields_absent`: every optional field left out:
  a slot without `target`, `verified_version`, `applied_version` and
  `in_use`, a Sysmon without `version`, an entry without
  `last_success_at`, a clock without `offset`, hardware without SMBIOS
  fields.
- `status_report:empty_lists`: no document slot, no telemetry entry and
  no problem.
- `status_report:optional_fields_present`: every optional field present:
  slots of each target kind and slot state, a document in use from a
  prior epoch, a Sysmon version, a last success with nanoseconds, a
  negative clock offset, both SMBIOS fields.
- `status_report:every_problem`: every `Problem`, among them
  `sysmon_stopped`, `sysmon_config_changed` and `unexpected_restart`, a
  `signature_rejected` with and without `typ` and `kid`, and a tag the
  crate does not know, `disk_full`.
- `status_report:unknown_tags`: a tag the crate does not know in each
  field that takes one.

`active_list.json`:

- `list_update:full_every_state`: a `full` list of five entries, one in
  each state: `active`, `license_pending`, and `suspended` for
  `revoked`, `operator` and `license`.
- `list_update:full_empty`: a `full` list with no entry.
- `list_update:diff_every_state`: a `diff` upserting five entries, one
  in each state, and removing two endpoints.
- `list_update:diff_removals_only`: a `diff` that only removes one
  endpoint.

## `trust_chain.json`

Each case verifies one install configuration's trust chain.

- `input.install_config`: the `senta-install-config` JWS.
- `input.vendor_keys`: the kids, in the key list, of the vendor public
  keys the verifier trusts. A kid that follows no vendor prefix, such as
  `vendor-other-1`, cannot be in this list.
- `input.trust_test_keys`: whether vendor test keys
  (`vendor-test-<number>`) are trusted.
- `expected`: `{"installed": …}` or `{"install_failed": …}`.

## `hardware_hash.json`

Each case hashes one machine identifier.

- `input.machine_id_kind`: `linux` for a Linux machine-id, `windows` for
  a Windows MachineGuid.
- `input.machine_id`: the identifier as read. A machine-id is 32
  hexadecimal digits of either case. A MachineGuid is hexadecimal digits
  of either case in the groups `8-4-4-4-12`, with or without braces.
- `input.hw_salt`: the install's 32-byte `hw_salt`.
- `expected.machine_id_hash`: the 32-byte hash.

The hash is HMAC-SHA256 keyed with the identifier's 16 bytes, over the
ASCII `clumit-endpoint` followed by the 32 bytes of `hw_salt`. The 16
bytes are the hexadecimal digits decoded in the order written: for a
MachineGuid that is RFC 4122 byte order, the digits as they stand in the
`8-4-4-4-12` notation, not the little-endian field order of the Windows
`GUID` structure. A machine-id and a MachineGuid of the same 16 bytes,
in either case and with or without braces, have the same hash.

## Sequence files

`keyset.json`, `leak.json`, `document_versions.json`,
`enroll_result.json` and `commands.json` hold sequence cases: a starting
state, then steps taken in order, each with its own expected result.

- `initial`: what the starting state is built from, as in
  `trust_chain.json`: `install_config`, `vendor_keys` and
  `trust_test_keys`. Every case starts from an install configuration
  whose chain verifies; nothing outside the file adds to the state.
- `steps`: the steps, each with:
  - `action`: what the step does (below);
  - `input`: what the action takes;
  - `env`: the step's environment: the endpoint's own clock and the
    like;
  - `expected`: the step's result;
  - `state` (optional): the state expected after the step (below).

### Starting state and how steps change it

1. Verify `initial` as a trust chain. Its trust state is stored as the
   endpoint's trust state, and its address document makes the first
   document version state: at the key set's recovery epoch, with no
   endpoint id, and the address slot holding the install configuration's
   address document as verified and applied.
2. There is no command state until an enrollment step succeeds. Its
   `endpoint_id` becomes the endpoint's id, and the command state starts
   at that point: that endpoint id, the current recovery epoch, no
   sequence floor and no records. A later successful enrollment with the
   same id keeps the command state as it is.
3. Each step is given the trust state stored last.
4. A step that changes the trust state (`receive_keyset`,
   `receive_chain`, `receive_enroll_result`,
   `receive_enroll_result_message`) stores it first. Then each recovery
   epoch change it brought, in order, restarts the document versions for
   the new epoch, and the command state's sequence floor if there is a
   command state. `receive_documents_message` does the same within the
   action.
5. Every document is applied successfully; no case has an application
   that fails.

### Actions

- `receive_keyset`: `input.jws`, one `senta-keyset`. `expected`: its
  `DocumentResult`.
- `receive_chain`: `input.documents`, `senta-keyset` and
  `senta-recovery-key` JWSs taken in order as a catch-up chain.
  `expected`: one result per document in the order of the list, a
  `DocumentResult` or `"not_processed"` after the document the chain
  stopped at.
- `receive_enroll_result`: `input.chain`, the catch-up chain, and
  `input.enroll_result`, the `senta-enroll-result` JWS. `env.attempt`:
  the attempt the result is held against, with `spki_sha256` (the
  endpoint's own), `attempt_id` and `token_id`. `expected`:
  `{"chain": [<result per chain document>], "result": <enrollment>}`.
- `receive_enroll_result_message`: as `receive_enroll_result`, with the
  chain and the result carried in `input.message`: the bytes of an
  approved `enroll_result` control message. They are the CBOR envelope
  `[t, b]`, the payload of the frame without its 4-byte length prefix;
  the body's approved outcome holds the `enroll_result` JWS and the
  `chain` list.
- `receive_document`: `input.jws`, one `senta-policy`, `senta-assign`,
  `senta-addresses` or `senta-update`. `env.now` and
  `env.senta_version`, the senta version installed. `expected`: its
  `DocumentResult`.
- `receive_documents_message`: `input.message`, the bytes of a
  `documents` control message, encoded as for
  `receive_enroll_result_message`, whose body's `documents` list holds
  the JWSs of one `Documents` message; with `env.now` and
  `env.senta_version`. `expected`: one result per document in the order
  of the list, a `DocumentResult` or `"not_processed"`.
- `receive_command`: `input.jws`, one `senta-command`, with `env.now`.
  `expected`: `"execute"`, or the `CommandResultKind` to report.
- `finish_command`: `input.command_id` and `input.result`, the
  `CommandResultKind` an accepted command finished with. `expected`:
  `"ok"`.

### Expected state

`state` names only what the case looks at; a member left out is not
checked.

- `keyset`: `{"recovery_epoch": …, "keyset_version": …}` of the trust
  state's key set.
- `recovery_key_version`: the version of the recovery key trusted.
- `slot`: one document version slot, with:
  - `slot`: `"assign"`, `"addresses"`, `"endpoint_update"`,
    `{"policy": <group_id>}` or `{"group_update": <group_id>}`;
  - `verified_version`, `applied_version`: the slot's versions in the
    current recovery epoch, `null` when it has none.
- `last_seq`: the `seq` of the last command accepted in the current
  recovery epoch, `null` when none has been.
- `endpoint_id`: the endpoint's id, `null` before it has enrolled.

### Versions and sequence numbers

The documents an issuing side would make in the ordinary way carry
versions and `seq`s by its rule: the Unix time in milliseconds of the
document's issue time, or, when that is not above the previous value for
the same (`typ`, target) or the same endpoint, the previous value + 1.
Documents that break the rule on purpose, and documents sent again,
carry the values their case sets, such as the largest integer
9007199254740991 for a forged `seq`.
