//! Length-prefixed frames: a four-byte big-endian length, then that many
//! bytes holding one CBOR value.

use std::fmt;

use super::cbor::{self, EncodeError};
use super::message::Message;

/// The limit a server receives under from an endpoint whose SPKI is
/// active: 4 MiB.
pub const SERVER_ACTIVE_RECEIVE_LIMIT: u32 = 4 * 1024 * 1024;

/// The limit a server receives under from an endpoint in any other
/// standing (not listed, waiting for a license, or suspended): 64 KiB.
pub const SERVER_OTHER_RECEIVE_LIMIT: u32 = 64 * 1024;

/// The limit an endpoint receives under, whatever its standing: 4 MiB.
pub const ENDPOINT_RECEIVE_LIMIT: u32 = 4 * 1024 * 1024;

const LENGTH_PREFIX: usize = 4;

/// The bytes of one encoded frame, length prefix included, ready to be
/// written to the connection.
#[derive(Clone, PartialEq, Eq)]
pub struct Frame(Vec<u8>);

impl Frame {
    /// Encodes a payload as a frame: its length as four big-endian bytes,
    /// then the payload.
    ///
    /// The payload is not checked to be CBOR.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload is longer than `u32::MAX` bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, EncodeError> {
        let len = u32::try_from(payload.len()).map_err(|_| {
            EncodeError::new(format!(
                "a payload of {} bytes does not fit a frame",
                payload.len()
            ))
        })?;
        let mut bytes = Vec::with_capacity(LENGTH_PREFIX + payload.len());
        bytes.extend_from_slice(&len.to_be_bytes());
        bytes.extend_from_slice(payload);
        Ok(Self(bytes))
    }

    /// Encodes an envelope `[t, b]` with the given `t` and body as a frame.
    ///
    /// # Errors
    ///
    /// Returns an error when the body fails to encode or the envelope is
    /// longer than `u32::MAX` bytes.
    pub fn new<B: serde::Serialize + ?Sized>(t: &str, body: &B) -> Result<Self, EncodeError> {
        let body = cbor::to_vec(body)?;
        Self::from_payload(&super::envelope::encode(t, &body)?)
    }

    /// Encodes a message as a frame, under its own `t`.
    ///
    /// # Errors
    ///
    /// Returns an error when the message fails to encode or the envelope
    /// is longer than `u32::MAX` bytes.
    pub fn from_message<M: Message>(message: &M) -> Result<Self, EncodeError> {
        Self::new(M::T, message)
    }

    /// Returns the frame's bytes, length prefix included.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the bytes after the length prefix.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        self.0.get(LENGTH_PREFIX..).unwrap_or_default()
    }

    /// Returns the frame's bytes, length prefix included.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("payload_len", &self.payload().len())
            .finish_non_exhaustive()
    }
}

impl AsRef<[u8]> for Frame {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A frame whose length prefix declares more bytes than the receiver
/// accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameTooLarge {
    /// The length the prefix declares.
    pub length: u32,
    /// The limit it was checked against.
    pub limit: u32,
}

impl fmt::Display for FrameTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a frame of {} bytes exceeds the limit of {} bytes",
            self.length, self.limit
        )
    }
}

impl std::error::Error for FrameTooLarge {}

/// A decoder that splits received bytes, in pieces of any size, into
/// frames.
///
/// A frame's length prefix is checked against the limit as soon as its
/// four bytes are in, before any of the body is waited for; a length equal
/// to the limit is accepted. The limit can be changed at any time, and
/// applies from the next length prefix read: a frame whose prefix was
/// already accepted completes under the limit it was accepted under. Once a
/// frame is refused, the decoder stays failed.
#[derive(Clone)]
pub struct FrameDecoder {
    limit: u32,
    buf: Vec<u8>,
    start: usize,
    body_len: Option<usize>,
    failed: Option<FrameTooLarge>,
}

impl FrameDecoder {
    /// Creates a decoder that accepts frames of up to `limit` bytes after
    /// the length prefix.
    #[must_use]
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            buf: Vec::new(),
            start: 0,
            body_len: None,
            failed: None,
        }
    }

    /// Returns the limit the next length prefix is checked against.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// Sets the limit the next length prefix is checked against.
    pub fn set_limit(&mut self, limit: u32) {
        self.limit = limit;
    }

    /// Adds received bytes.
    pub fn push(&mut self, bytes: &[u8]) {
        if self.failed.is_some() {
            return;
        }
        // Drop what has been consumed once it is most of the buffer, so
        // feeding a long frame a byte at a time stays linear.
        if self.start > 0 && self.start * 2 >= self.buf.len() {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// Returns the next complete frame's payload, or `None` when the bytes
    /// so far do not complete one.
    ///
    /// # Errors
    ///
    /// Returns an error when a length prefix exceeds the limit, and on
    /// every call after that.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameTooLarge> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let pending = self.buf.get(self.start..).unwrap_or_default();
        let len = match self.body_len {
            Some(len) => len,
            None => {
                let Some(prefix) = pending.first_chunk::<LENGTH_PREFIX>() else {
                    return Ok(None);
                };
                let length = u32::from_be_bytes(*prefix);
                let accepted = usize::try_from(length)
                    .ok()
                    .filter(|_| length <= self.limit);
                let Some(len) = accepted else {
                    let error = FrameTooLarge {
                        length,
                        limit: self.limit,
                    };
                    self.failed = Some(error);
                    self.buf = Vec::new();
                    return Err(error);
                };
                self.start += LENGTH_PREFIX;
                self.body_len = Some(len);
                len
            }
        };
        let body_start = self.start;
        let Some(end) = body_start.checked_add(len) else {
            return Ok(None);
        };
        let Some(payload) = self.buf.get(body_start..end) else {
            return Ok(None);
        };
        let payload = payload.to_vec();
        self.start = end;
        self.body_len = None;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
        Ok(Some(payload))
    }
}

impl fmt::Debug for FrameDecoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameDecoder")
            .field("limit", &self.limit)
            .field("buffered", &self.buf.len().saturating_sub(self.start))
            .field("body_len", &self.body_len)
            .field("failed", &self.failed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_of(len: u32) -> Vec<u8> {
        let mut bytes = len.to_be_bytes().to_vec();
        bytes.resize(4 + usize::try_from(len).unwrap(), 0);
        bytes
    }

    #[test]
    fn encoder_writes_a_big_endian_length_then_the_payload() {
        let frame = Frame::from_payload(&[0x82, 0x01, 0x02]).unwrap();
        assert_eq!(frame.as_bytes(), [0, 0, 0, 3, 0x82, 0x01, 0x02]);
        assert_eq!(frame.payload(), [0x82, 0x01, 0x02]);
        let empty = Frame::from_payload(&[]).unwrap();
        assert_eq!(empty.as_bytes(), [0, 0, 0, 0]);
    }

    #[test]
    fn decoder_returns_what_the_encoder_wrote_whole_or_byte_by_byte() {
        let payloads: [&[u8]; 3] = [&[0x82, 0x01, 0x02], &[], &[0xa0; 300]];
        let mut stream = Vec::new();
        for payload in payloads {
            stream.extend_from_slice(Frame::from_payload(payload).unwrap().as_bytes());
        }

        let mut whole = FrameDecoder::new(1024);
        whole.push(&stream);
        let mut got = Vec::new();
        while let Some(payload) = whole.next_frame().unwrap() {
            got.push(payload);
        }
        assert_eq!(got, payloads);

        let mut single = FrameDecoder::new(1024);
        let mut got = Vec::new();
        for byte in &stream {
            single.push(std::slice::from_ref(byte));
            while let Some(payload) = single.next_frame().unwrap() {
                got.push(payload);
            }
        }
        assert_eq!(got, payloads);
    }

    #[test]
    fn limits_accept_exactly_the_limit_and_refuse_one_more_before_the_body() {
        for limit in [SERVER_OTHER_RECEIVE_LIMIT, SERVER_ACTIVE_RECEIVE_LIMIT] {
            let mut decoder = FrameDecoder::new(limit);
            decoder.push(&frame_of(limit));
            let payload = decoder.next_frame().unwrap().unwrap();
            assert_eq!(payload.len(), usize::try_from(limit).unwrap());

            // Only the four prefix bytes: refused without any body.
            let mut decoder = FrameDecoder::new(limit);
            decoder.push(&(limit + 1).to_be_bytes());
            let error = decoder.next_frame().unwrap_err();
            assert_eq!(
                error,
                FrameTooLarge {
                    length: limit + 1,
                    limit
                }
            );
            assert_eq!(decoder.next_frame(), Err(error));
        }
        assert_eq!(ENDPOINT_RECEIVE_LIMIT, 4_194_304);
        assert_eq!(SERVER_ACTIVE_RECEIVE_LIMIT, 4_194_304);
        assert_eq!(SERVER_OTHER_RECEIVE_LIMIT, 65_536);
    }

    #[test]
    fn a_lowered_limit_applies_from_the_next_prefix() {
        let big = frame_of(SERVER_OTHER_RECEIVE_LIMIT + 1);

        let mut decoder = FrameDecoder::new(SERVER_ACTIVE_RECEIVE_LIMIT);
        decoder.push(&big);
        assert!(decoder.next_frame().unwrap().is_some());
        decoder.set_limit(SERVER_OTHER_RECEIVE_LIMIT);
        decoder.push(big.get(..4).unwrap());
        assert_eq!(
            decoder.next_frame(),
            Err(FrameTooLarge {
                length: SERVER_OTHER_RECEIVE_LIMIT + 1,
                limit: SERVER_OTHER_RECEIVE_LIMIT
            })
        );

        // A prefix already accepted completes under the old limit.
        let mut decoder = FrameDecoder::new(SERVER_ACTIVE_RECEIVE_LIMIT);
        decoder.push(big.get(..10).unwrap());
        assert_eq!(decoder.next_frame(), Ok(None));
        decoder.set_limit(SERVER_OTHER_RECEIVE_LIMIT);
        decoder.push(big.get(10..).unwrap());
        assert!(decoder.next_frame().unwrap().is_some());
        assert_eq!(decoder.limit(), SERVER_OTHER_RECEIVE_LIMIT);
    }
}
