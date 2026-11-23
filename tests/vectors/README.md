# Test vectors

The files here are language-neutral test vectors for the trust contracts
of this crate: JWS verification, the install configuration trust chain,
the key set, document version and command state machines, enrollment
results and the hardware identifier hash. A signer or a verifier written
in another language reads them to check that it follows the same rules
as the crate: it builds the same bytes from the same inputs, and reaches
the same result for each case.

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
- Bytes are unpadded base64url (RFC 4648 section 5, no `=`).
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
  `hardware_hash.json`, which uses none.
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

The other results are written as below. None of their tags is a tag of
the three enums, nor of one another.

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
