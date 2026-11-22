# senta-protocol

senta-protocol holds the protocol, record formats and trust contracts
shared by Clumit Endpoint (senta, a private repository), REview and the
event store. It is one Rust crate whose features select the
part a consumer needs: `auth`, `control`, `telemetry` and `test-util`.

## Status

Early concept. The crate skeleton is in place: the `auth`, `control`
and `telemetry` features each turn on a module of their own, and no
protocol is implemented in them yet.

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
