# senta-protocol

senta-protocol holds the protocol, record formats and trust contracts
shared by Clumit Endpoint (senta, a private repository), REview and the
event store. It is one Rust crate whose features select the
part a consumer needs: `auth`, `control`, `telemetry` and `test-util`.

## Status

Early concept. The `auth`, `control` and `telemetry` features each turn
on a module of their own. `auth` holds the JWS verifier for signed
documents, with the kid grammar, the `typ` values and the key kinds
allowed to sign each, and the strict JSON parsing their contents go
through. It also holds the endpoint's document version state machine:
which version of each policy, group assignment, address document and
update it has verified and applied, how a recovery epoch starts them
over, and how the documents of one `Documents` message are taken in
order; and the trust chain of an install configuration, from the vendor
keys the caller passes in through the deployment certificate and the
install signing key to the key set, the address document and the
enrollment token, which gives the endpoint its first trust state and
its first document version state. `test-util` adds, with `auth`,
deterministic test keys and a signer for building signed documents in
tests. The `connection` module,
public whatever the features, holds what control and telemetry
connections share: framing, the envelope, the CBOR rules, version
negotiation, liveness, reconnection backoff and clock correction. The
`host` module, also public whatever the features, holds the operating
system and collection mode an endpoint reports about its host.
`telemetry` holds the record format: the host header, the open body,
the fixed record bytes and their hash, the network state source rule,
the record kind registry, and the bodies of the Windows event log,
journald and auditd kinds. No other protocol is implemented yet.

## License

Copyright 2026 ClumL Inc.

Licensed under [Apache License, Version 2.0][apache-license] (the "License");
you may not use this crate except in compliance with the License.

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See [LICENSE](LICENSE) for
the specific language governing permissions and limitations under the License.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the [Apache-2.0
license][apache-license], shall be licensed as above, without any additional
terms or conditions.

[apache-license]: http://www.apache.org/licenses/LICENSE-2.0
