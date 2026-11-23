//! The messages of a telemetry connection: opening and resuming a stream,
//! carrying its records, acknowledging them, reporting what was dropped or
//! lost, closing it, and refusing what was received.

use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::connection::{Body, DecodeError, EncodeError, Frame, Message, cbor};
use crate::telemetry_codes::{DropReason, TelemetryError};

/// The longest a record may be, in bytes: 256 KiB.
pub const MAX_RECORD_LEN: usize = 262_144;

/// The longest the records of one batch may be together, in bytes: 1 MiB.
pub const MAX_BATCH_LEN: usize = 1_048_576;

/// The `t` of every telemetry message, to pass to a connection helper as
/// the kinds of message it knows.
pub const TELEMETRY_MESSAGE_KINDS: [&str; 8] = [
    OpenStream::T,
    ResumeInfo::T,
    RecordBatch::T,
    Ack::T,
    DroppedRange::T,
    LostOnReset::T,
    CloseStream::T,
    ErrorMessage::T,
];

/// A range of sequence numbers, both ends included.
///
/// Nothing checks that `from` is at most `to`: a range is carried as it
/// is, so that its receiver can refuse it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SeqRange {
    /// The first sequence number of the range.
    pub from: u64,
    /// The last sequence number of the range.
    pub to: u64,
}

/// The last record a telemetry entry stored in a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LastStored {
    /// The record's sequence number, `L`.
    pub seq: u64,
    /// The record's hash, `H`: the first 16 bytes of the SHA-256 of its
    /// bytes, as [`crate::telemetry::record_hash`] computes it.
    #[serde(with = "cbor::bytes")]
    pub hash: [u8; 16],
}

/// Opens a stream, or resumes one, on this connection. Sent by the
/// endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpenStream {
    /// The stream's id.
    #[serde(with = "cbor::uuid")]
    pub stream: Uuid,
}

impl Message for OpenStream {
    const T: &'static str = "open_stream";
}

/// Where a stream stands at the telemetry entry, answering an
/// [`OpenStream`]. Sent by the entry.
///
/// Nothing checks that `last_stored.seq` is at most `a`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResumeInfo {
    /// The stream's id.
    #[serde(with = "cbor::uuid")]
    pub stream: Uuid,
    /// The highest sequence number acknowledged, `A`.
    pub a: u64,
    /// The last record stored, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_stored: Option<LastStored>,
}

impl Message for ResumeInfo {
    const T: &'static str = "resume_info";
}

/// Records of one stream, in order. Sent by the endpoint.
///
/// Each record is its bytes as the sender fixed them, carried as a CBOR
/// byte string. A batch neither decodes nor re-encodes them, so the bytes
/// received are the bytes sent, bit for bit, and hash the same. An empty
/// batch is valid.
///
/// No record may be longer than [`MAX_RECORD_LEN`] bytes, and the records
/// together, not counting the CBOR around them, no longer than
/// [`MAX_BATCH_LEN`] bytes. [`RecordBatch::new`] and decoding both refuse
/// a batch past either limit, so no `RecordBatch` holds one.
///
/// The batch's `stream` must be the `stream` in the header of every record
/// it holds. A receiver stores and acknowledges none of a batch in which
/// any record names another stream. The batch carries the stream so that
/// the receiver can judge the stream's state without decoding a record;
/// comparing it with the records' headers is the receiver's work, not
/// this type's, which never looks inside a record.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "UncheckedBatch")]
pub struct RecordBatch {
    #[serde(with = "cbor::uuid")]
    stream: Uuid,
    #[serde(with = "record_list")]
    records: Vec<Vec<u8>>,
}

impl Message for RecordBatch {
    const T: &'static str = "record_batch";
}

impl RecordBatch {
    /// Creates a batch of `records` for `stream`.
    ///
    /// # Errors
    ///
    /// Returns an error when a record is longer than [`MAX_RECORD_LEN`]
    /// bytes, or the records together are longer than [`MAX_BATCH_LEN`]
    /// bytes.
    pub fn new(stream: Uuid, records: Vec<Vec<u8>>) -> Result<Self, RecordBatchTooLarge> {
        check_sizes(&records)?;
        Ok(Self { stream, records })
    }

    /// Returns the id of the stream the records belong to.
    #[must_use]
    pub fn stream(&self) -> Uuid {
        self.stream
    }

    /// Returns the records' bytes.
    #[must_use]
    pub fn records(&self) -> &[Vec<u8>] {
        &self.records
    }

    /// Returns the records' bytes, consuming the batch.
    #[must_use]
    pub fn into_records(self) -> Vec<Vec<u8>> {
        self.records
    }
}

/// A batch past a size limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordBatchTooLarge {
    /// A record is longer than [`MAX_RECORD_LEN`] bytes.
    Record {
        /// The record's position in the batch, from 0.
        index: usize,
        /// The record's length in bytes.
        len: usize,
    },
    /// The records together are longer than [`MAX_BATCH_LEN`] bytes.
    Batch {
        /// The records' total length in bytes, saturating at `usize::MAX`.
        len: usize,
    },
}

impl fmt::Display for RecordBatchTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Record { index, len } => write!(
                f,
                "record {index} is {len} bytes, more than the {MAX_RECORD_LEN} a record may be"
            ),
            Self::Batch { len } => write!(
                f,
                "the records are {len} bytes together, more than the {MAX_BATCH_LEN} a batch may \
                 hold"
            ),
        }
    }
}

impl std::error::Error for RecordBatchTooLarge {}

/// Checks the records of a batch against both size limits.
fn check_sizes(records: &[Vec<u8>]) -> Result<(), RecordBatchTooLarge> {
    let mut total: usize = 0;
    for (index, record) in records.iter().enumerate() {
        let len = record.len();
        if len > MAX_RECORD_LEN {
            return Err(RecordBatchTooLarge::Record { index, len });
        }
        total = total.saturating_add(len);
    }
    if total > MAX_BATCH_LEN {
        return Err(RecordBatchTooLarge::Batch { len: total });
    }
    Ok(())
}

/// A batch as decoded, before its sizes are checked.
#[derive(Deserialize)]
struct UncheckedBatch {
    #[serde(with = "cbor::uuid")]
    stream: Uuid,
    #[serde(with = "record_list")]
    records: Vec<Vec<u8>>,
}

impl TryFrom<UncheckedBatch> for RecordBatch {
    type Error = RecordBatchTooLarge;

    fn try_from(batch: UncheckedBatch) -> Result<Self, Self::Error> {
        Self::new(batch.stream, batch.records)
    }
}

/// A serde helper writing a list of byte values as an array of CBOR byte
/// strings.
mod record_list {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::connection::cbor;

    struct Record<'a>(&'a [u8]);

    impl Serialize for Record<'_> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            cbor::bytes::serialize(self.0, serializer)
        }
    }

    struct OwnedRecord(Vec<u8>);

    impl<'de> Deserialize<'de> for OwnedRecord {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            cbor::bytes::deserialize(deserializer).map(OwnedRecord)
        }
    }

    pub(super) fn serialize<S: Serializer>(
        records: &[Vec<u8>],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(records.iter().map(|record| Record(record)))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        let records = Vec::<OwnedRecord>::deserialize(deserializer)?;
        Ok(records.into_iter().map(|record| record.0).collect())
    }
}

/// Acknowledges every record of a stream up to and including `a`. Sent by
/// the entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ack {
    /// The stream's id.
    #[serde(with = "cbor::uuid")]
    pub stream: Uuid,
    /// The highest sequence number acknowledged, `A`.
    pub a: u64,
}

impl Message for Ack {
    const T: &'static str = "ack";
}

/// Reports that the endpoint dropped the records `from` to `to`, both
/// included, of a stream, and why. Sent by the endpoint.
///
/// Nothing checks that `from` is at most `to`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DroppedRange {
    /// The stream's id.
    #[serde(with = "cbor::uuid")]
    pub stream: Uuid,
    /// The first sequence number dropped.
    pub from: u64,
    /// The last sequence number dropped.
    pub to: u64,
    /// Why the records were dropped.
    pub reason: DropReason,
}

impl Message for DroppedRange {
    const T: &'static str = "dropped_range";
}

/// Reports the records of a stream that were lost when the endpoint's
/// state was reset, and that will never be sent. Sent by the endpoint.
///
/// An empty list of ranges is valid, and nothing checks the ranges.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LostOnReset {
    /// The id of the stream the records were lost from.
    #[serde(with = "cbor::uuid")]
    pub old_stream: Uuid,
    /// The ranges of sequence numbers lost.
    pub ranges: Vec<SeqRange>,
}

impl Message for LostOnReset {
    const T: &'static str = "lost_on_reset";
}

/// Closes a stream. Sent by the endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CloseStream {
    /// The stream's id.
    #[serde(with = "cbor::uuid")]
    pub stream: Uuid,
}

impl Message for CloseStream {
    const T: &'static str = "close_stream";
}

/// Refuses what was received, for the reason given. Sent by the entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ErrorMessage {
    /// The id of the stream whose message the error answers, or `None`
    /// when the error is not about a stream, as with
    /// [`TelemetryError::NotListed`], [`TelemetryError::Suspended`] and
    /// [`TelemetryError::LeaseExpired`]. This pairing is a contract on the
    /// sender; decoding does not check it.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "cbor::uuid::option"
    )]
    pub stream: Option<Uuid>,
    /// Why it was refused.
    pub error: TelemetryError,
}

impl Message for ErrorMessage {
    const T: &'static str = "error";
}

/// Any telemetry message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TelemetryMessage {
    /// An `open_stream`.
    OpenStream(OpenStream),
    /// A `resume_info`.
    ResumeInfo(ResumeInfo),
    /// A `record_batch`.
    RecordBatch(RecordBatch),
    /// An `ack`.
    Ack(Ack),
    /// A `dropped_range`.
    DroppedRange(DroppedRange),
    /// A `lost_on_reset`.
    LostOnReset(LostOnReset),
    /// A `close_stream`.
    CloseStream(CloseStream),
    /// An `error`.
    ErrorMessage(ErrorMessage),
}

impl TelemetryMessage {
    /// Decodes the body of the telemetry message named `t`.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryDecodeError::UnknownKind`] when `t` is not one
    /// of [`TELEMETRY_MESSAGE_KINDS`], [`TelemetryDecodeError::BatchTooLarge`]
    /// when the body is a `record_batch` that decodes but is past a size
    /// limit, and [`TelemetryDecodeError::Malformed`] when the body does
    /// not decode.
    pub fn decode(t: &str, body: &Body) -> Result<Self, TelemetryDecodeError> {
        match t {
            OpenStream::T => decode_body(t, body).map(Self::OpenStream),
            ResumeInfo::T => decode_body(t, body).map(Self::ResumeInfo),
            RecordBatch::T => {
                let batch: UncheckedBatch = decode_body(t, body)?;
                let stream = batch.stream;
                RecordBatch::try_from(batch)
                    .map(Self::RecordBatch)
                    .map_err(|_| TelemetryDecodeError::BatchTooLarge { stream })
            }
            Ack::T => decode_body(t, body).map(Self::Ack),
            DroppedRange::T => decode_body(t, body).map(Self::DroppedRange),
            LostOnReset::T => decode_body(t, body).map(Self::LostOnReset),
            CloseStream::T => decode_body(t, body).map(Self::CloseStream),
            ErrorMessage::T => decode_body(t, body).map(Self::ErrorMessage),
            _ => Err(TelemetryDecodeError::UnknownKind { t: t.to_owned() }),
        }
    }

    /// Returns the message's `t`.
    #[must_use]
    pub fn t(&self) -> &'static str {
        match self {
            Self::OpenStream(_) => OpenStream::T,
            Self::ResumeInfo(_) => ResumeInfo::T,
            Self::RecordBatch(_) => RecordBatch::T,
            Self::Ack(_) => Ack::T,
            Self::DroppedRange(_) => DroppedRange::T,
            Self::LostOnReset(_) => LostOnReset::T,
            Self::CloseStream(_) => CloseStream::T,
            Self::ErrorMessage(_) => ErrorMessage::T,
        }
    }

    /// Encodes the message as a frame holding the envelope `[t, b]`.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope is longer than `u32::MAX` bytes.
    pub fn to_frame(&self) -> Result<Frame, EncodeError> {
        match self {
            Self::OpenStream(message) => Frame::from_message(message),
            Self::ResumeInfo(message) => Frame::from_message(message),
            Self::RecordBatch(message) => Frame::from_message(message),
            Self::Ack(message) => Frame::from_message(message),
            Self::DroppedRange(message) => Frame::from_message(message),
            Self::LostOnReset(message) => Frame::from_message(message),
            Self::CloseStream(message) => Frame::from_message(message),
            Self::ErrorMessage(message) => Frame::from_message(message),
        }
    }
}

/// Decodes a body, naming `t` if it fails.
fn decode_body<T: serde::de::DeserializeOwned>(
    t: &str,
    body: &Body,
) -> Result<T, TelemetryDecodeError> {
    body.decode()
        .map_err(|error| TelemetryDecodeError::Malformed {
            t: t.to_owned(),
            error,
        })
}

/// Why a telemetry message did not decode.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TelemetryDecodeError {
    /// `t` names no telemetry message.
    UnknownKind {
        /// The `t` received.
        t: String,
    },
    /// The body of a telemetry message did not decode.
    Malformed {
        /// The message's `t`.
        t: String,
        /// Why it did not decode.
        error: DecodeError,
    },
    /// A `record_batch` decoded but is past a size limit: a record longer
    /// than [`MAX_RECORD_LEN`] bytes, or records longer than
    /// [`MAX_BATCH_LEN`] bytes together.
    BatchTooLarge {
        /// The `stream` of the batch.
        stream: Uuid,
    },
}

impl fmt::Display for TelemetryDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKind { t } => write!(f, "{t:?} is not a telemetry message"),
            Self::Malformed { t, error } => write!(f, "body of {t:?}: {error}"),
            Self::BatchTooLarge { stream } => {
                write!(f, "record batch of stream {stream} is past a size limit")
            }
        }
    }
}

impl std::error::Error for TelemetryDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Malformed { error, .. } => Some(error),
            Self::UnknownKind { .. } | Self::BatchTooLarge { .. } => None,
        }
    }
}
