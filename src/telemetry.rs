//! Telemetry records.
//!
//! A telemetry connection carries [`Record`]s: a host header
//! ([`RecordHeader`]), the record kind's number and the schema version of
//! its body, and the body itself, an open map ([`RecordBody`]) that each
//! kind's own type reads. Records follow the CBOR rules of
//! [`crate::connection::cbor`], and IP addresses the helper [`ip`].
//!
//! The sender fixes a record's bytes once with [`Record::to_bytes`],
//! resends exactly those bytes, and hashes them with [`record_hash`]; a
//! receiver hashes the bytes it received, so receivers of every version
//! compute the same hash. [`resolve_net_state`] decides which network state
//! a header carries, and [`kind`] is the registry of record kinds.
//!
//! ```
//! use jiff::Timestamp;
//! use senta_protocol::host::{CollectionMode, OsFamily, OsInfo};
//! use senta_protocol::telemetry::{
//!     NetStateSource, Record, RecordBody, RecordHeader, kind, record_hash,
//! };
//! use serde::{Deserialize, Serialize};
//! use uuid::Uuid;
//!
//! #[derive(Debug, PartialEq, Serialize, Deserialize)]
//! struct Body {
//!     image: String,
//! }
//!
//! let record = Record {
//!     header: RecordHeader {
//!         endpoint_id: Uuid::from_u128(1),
//!         stream: Uuid::from_u128(2),
//!         seq: 0,
//!         event_time: Timestamp::from_second(1_700_000_000)?,
//!         collected_at: Timestamp::from_second(1_700_000_001)?,
//!         clock_offset: None,
//!         hostname: "host-1".to_owned(),
//!         ips: vec!["192.0.2.10".parse()?],
//!         default_route_ip: None,
//!         net_state_source: NetStateSource::Observed,
//!         os: OsInfo {
//!             family: OsFamily::Windows,
//!             version: "10.0.22631".to_owned(),
//!         },
//!         collection_mode: CollectionMode::Essential,
//!         process_key: None,
//!     },
//!     kind: kind::SYSMON_PROCESS_CREATE,
//!     schema: 1,
//!     body: RecordBody::encode(&Body { image: "cmd.exe".to_owned() })?,
//! };
//! let bytes = record.to_bytes()?;
//! let hash = record_hash(&bytes);
//!
//! let received = Record::from_bytes(&bytes)?;
//! assert_eq!(received.body.decode::<Body>()?.image, "cmd.exe");
//! assert_eq!(record_hash(&bytes), hash);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

pub mod ip;
pub mod kind;
pub mod logs;
mod net_state;
mod record;

pub use self::net_state::{
    NetState, NetStateGap, NetStateSpan, ResolvedNetState, resolve_net_state,
};
pub use self::record::{
    NetStateSource, ProcessKey, Record, RecordBody, RecordEncodeError, RecordHeader, record_hash,
};
