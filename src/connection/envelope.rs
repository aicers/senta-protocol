//! The envelope inside every frame: a CBOR array of exactly two elements,
//! `[t, b]`, where `t` names the message and `b` is its body.

use std::fmt;

use serde::de::DeserializeOwned;

use super::cbor::{self, DecodeError, EncodeError, Head, Reader, ScanError};

const ARRAY_OF_TWO: u8 = 0x82;
const MAJOR_TEXT: u8 = 3;

/// The ways a frame fails to hold an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// The frame is empty.
    Empty,
    /// The frame is not well-formed CBOR: truncated, a length longer than
    /// what follows it, a reserved encoding, a misplaced break, or a text
    /// string that is not UTF-8.
    Malformed,
    /// Bytes follow the CBOR value.
    TrailingBytes,
    /// The value is not an array.
    NotArray,
    /// The array is of indefinite length.
    IndefiniteLength,
    /// The array does not hold exactly two elements.
    WrongLength(u64),
    /// `t` is not a text string.
    TypeNotText,
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty frame"),
            Self::Malformed => f.write_str("frame is not well-formed CBOR"),
            Self::TrailingBytes => f.write_str("bytes follow the envelope"),
            Self::NotArray => f.write_str("envelope is not an array"),
            Self::IndefiniteLength => f.write_str("envelope is an indefinite-length array"),
            Self::WrongLength(len) => write!(f, "envelope has {len} elements, not 2"),
            Self::TypeNotText => f.write_str("envelope's t is not a text string"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

/// A message body `b`, as the CBOR bytes it arrived in, not yet decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body(Vec<u8>);

impl Body {
    /// Returns the body's CBOR bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Decodes the body into `T`, under the rules of [`cbor::from_slice`].
    ///
    /// # Errors
    ///
    /// Returns an error when the body holds a duplicate map key, nests too
    /// deeply, or does not decode into `T`.
    pub fn decode<T: DeserializeOwned>(&self) -> Result<T, DecodeError> {
        cbor::from_slice(&self.0)
    }
}

/// An envelope `[t, b]` checked for shape only: `t` is read and `b` is kept
/// as bytes, to be decoded when and as the reader chooses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    t: String,
    body: Body,
}

impl Envelope {
    /// Reads an envelope from a frame's payload.
    ///
    /// The payload must be exactly one well-formed CBOR value; that value
    /// must be an array of definite length two whose first element is a
    /// text string. Nothing about the body is checked beyond its being
    /// well-formed. No length declared in the payload is allocated before
    /// the payload is known to hold it.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload does not hold such an envelope.
    pub fn parse(payload: &[u8]) -> Result<Self, EnvelopeError> {
        if payload.is_empty() {
            return Err(EnvelopeError::Empty);
        }
        cbor::check_well_formed(payload).map_err(|error| match error {
            ScanError::TrailingBytes => EnvelopeError::TrailingBytes,
            _ => EnvelopeError::Malformed,
        })?;
        let mut reader = Reader::new(payload);
        match reader.head() {
            Ok(Head::Array(Some(2))) => {}
            Ok(Head::Array(Some(len))) => return Err(EnvelopeError::WrongLength(len)),
            Ok(Head::Array(None)) => return Err(EnvelopeError::IndefiniteLength),
            Ok(_) => return Err(EnvelopeError::NotArray),
            Err(_) => return Err(EnvelopeError::Malformed),
        }
        let Ok(Head::Text(len)) = reader.head() else {
            return Err(EnvelopeError::TypeNotText);
        };
        let mut t = Vec::new();
        reader
            .string(true, len, Some(&mut t))
            .map_err(|_| EnvelopeError::Malformed)?;
        let t = String::from_utf8(t).map_err(|_| EnvelopeError::Malformed)?;
        let body = payload
            .get(reader.position()..)
            .ok_or(EnvelopeError::Malformed)?;
        Ok(Self {
            t,
            body: Body(body.to_vec()),
        })
    }

    /// Returns the message's name, `t`.
    #[must_use]
    pub fn t(&self) -> &str {
        &self.t
    }

    /// Returns the undecoded body, `b`.
    #[must_use]
    pub fn body(&self) -> &Body {
        &self.body
    }

    /// Returns `t` and `b`.
    #[must_use]
    pub fn into_parts(self) -> (String, Body) {
        (self.t, self.body)
    }
}

/// Writes the CBOR of `[t, b]` from `t` and the CBOR of `b`.
pub(super) fn encode(t: &str, body: &[u8]) -> Result<Vec<u8>, EncodeError> {
    let len = u64::try_from(t.len()).map_err(|_| EncodeError::new("t is too long"))?;
    let mut out = Vec::with_capacity(1 + 9 + t.len() + body.len());
    out.push(ARRAY_OF_TWO);
    cbor::put_head(&mut out, MAJOR_TEXT, len);
    out.extend_from_slice(t.as_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::connection::cbor::DecodeErrorKind;

    #[test]
    fn encode_then_parse_round_trips() {
        let body = cbor::to_vec(&[1u8, 2]).unwrap();
        let payload = encode("ping", &body).unwrap();
        assert_eq!(payload.get(..6).unwrap(), b"\x82\x64ping");
        let envelope = Envelope::parse(&payload).unwrap();
        assert_eq!(envelope.t(), "ping");
        assert_eq!(envelope.body().as_bytes(), body);
        assert_eq!(envelope.body().decode::<Vec<u8>>().unwrap(), [1, 2]);

        let long = "x".repeat(300);
        let envelope = Envelope::parse(&encode(&long, &[0xf6]).unwrap()).unwrap();
        assert_eq!(envelope.t(), long);
    }

    #[test]
    fn envelope_errors() {
        let cases: [(&[u8], EnvelopeError); 10] = [
            (&[], EnvelopeError::Empty),
            (&[0x82, 0x61], EnvelopeError::Malformed),
            (&[0x1c], EnvelopeError::Malformed),
            (
                &[0x82, 0x61, b'a', 0x00, 0x00],
                EnvelopeError::TrailingBytes,
            ),
            (&[0x81, 0x61, b'a'], EnvelopeError::WrongLength(1)),
            (
                &[0x83, 0x61, b'a', 0x00, 0x00],
                EnvelopeError::WrongLength(3),
            ),
            (
                &[0x9f, 0x61, b'a', 0x00, 0xff],
                EnvelopeError::IndefiniteLength,
            ),
            (&[0xa1, 0x61, b'a', 0x00], EnvelopeError::NotArray),
            (&[0x82, 0x01, 0x00], EnvelopeError::TypeNotText),
            (&[0x82, 0x41, b'a', 0x00], EnvelopeError::TypeNotText),
        ];
        for (payload, expected) in cases {
            assert_eq!(Envelope::parse(payload), Err(expected), "{payload:02x?}");
        }
    }

    #[test]
    fn declared_lengths_past_the_frame_fail_as_malformed() {
        // A byte string declaring 2³²−1 bytes, then a few bytes.
        let payload = [0x82, 0x61, b'a', 0x5a, 0xff, 0xff, 0xff, 0xff, 1, 2, 3];
        assert_eq!(Envelope::parse(&payload), Err(EnvelopeError::Malformed));
        // An array declaring 2³²−1 elements.
        let payload = [0x82, 0x61, b'a', 0x9a, 0xff, 0xff, 0xff, 0xff, 1, 2, 3];
        assert_eq!(Envelope::parse(&payload), Err(EnvelopeError::Malformed));
        // A map declaring 2⁶⁴−1 pairs.
        let payload = [
            0x82, 0x61, b'a', 0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1,
        ];
        assert_eq!(Envelope::parse(&payload), Err(EnvelopeError::Malformed));
        // `t` itself declaring 2³²−1 bytes.
        let payload = [0x82, 0x7a, 0xff, 0xff, 0xff, 0xff, b'a', 0x00];
        assert_eq!(Envelope::parse(&payload), Err(EnvelopeError::Malformed));
    }

    #[test]
    fn t_reads_even_when_b_has_the_wrong_type() {
        #[derive(Debug, Deserialize)]
        struct Wanted {
            #[expect(dead_code, reason = "decoded only to see it fail")]
            sent_at: i64,
        }
        let payload = encode("ping", &cbor::to_vec("not a map").unwrap()).unwrap();
        let envelope = Envelope::parse(&payload).unwrap();
        assert_eq!(envelope.t(), "ping");
        assert!(envelope.body().decode::<Wanted>().is_err());
    }

    #[test]
    fn duplicate_body_keys_fail_at_body_decoding_not_parsing() {
        #[derive(Debug, Deserialize)]
        struct Body {}

        // A body of {null: 0, undefined: 1}: the envelope parses, and the
        // body fails only when it is decoded.
        let payload = encode("ping", &[0xa2, 0xf6, 0x00, 0xf7, 0x01]).unwrap();
        let envelope = Envelope::parse(&payload).unwrap();
        assert_eq!(envelope.t(), "ping");
        assert_eq!(
            envelope.body().decode::<Body>().unwrap_err().kind(),
            DecodeErrorKind::DuplicateKey
        );
    }

    #[test]
    fn indefinite_length_t_reads_as_text() {
        let payload = [0x82, 0x7f, 0x62, b'p', b'i', 0x62, b'n', b'g', 0xff, 0xa0];
        let envelope = Envelope::parse(&payload).unwrap();
        assert_eq!(envelope.t(), "ping");
        assert_eq!(envelope.body().as_bytes(), [0xa0]);
    }
}
