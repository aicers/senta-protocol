//! Ed25519 public keys and their JWK form.

use std::fmt;

use ed25519_dalek::VerifyingKey;
use serde::de::{self, MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::b64;

const JWK_NAME: &str = "Jwk";
const KTY: &str = "kty";
const CRV: &str = "crv";
const X: &str = "x";
const JWK_FIELDS: &[&str] = &[KTY, CRV, X];
const KTY_OKP: &str = "OKP";
const CRV_ED25519: &str = "Ed25519";
const PUBLIC_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// An Ed25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(VerifyingKey);

/// Bytes that are not an Ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not an Ed25519 public key")]
pub struct InvalidPublicKey;

impl PublicKey {
    /// Reads a public key from its 32-byte compressed form.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidPublicKey`] when `bytes` is not the encoding of a
    /// curve point.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self, InvalidPublicKey> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| InvalidPublicKey)
    }

    /// Returns the 32-byte compressed form of the key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0.to_bytes()
    }

    pub(crate) fn verifying_key(&self) -> &VerifyingKey {
        &self.0
    }

    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn from_verifying_key(key: VerifyingKey) -> Self {
        Self(key)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey")
            .field(&b64::encode(self.0.as_bytes()))
            .finish()
    }
}

/// An Ed25519 public key as a JWK, exactly
/// `{"kty":"OKP","crv":"Ed25519","x":<base64url>}`.
///
/// All three members are required and no other member is accepted: not
/// `kid`, `use`, `alg`, nor `d`. `x` is unpadded, canonical base64url of the
/// 32-byte key, and must be a curve point. A member that repeats is
/// rejected. The type reads as a field of a content type parsed with
/// [`super::strict::from_slice`], and on its own through that function too.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Jwk(PublicKey);

impl Jwk {
    /// Returns the public key.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        self.0
    }
}

impl From<PublicKey> for Jwk {
    fn from(key: PublicKey) -> Self {
        Self(key)
    }
}

impl From<Jwk> for PublicKey {
    fn from(jwk: Jwk) -> Self {
        jwk.0
    }
}

impl Serialize for Jwk {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut jwk = serializer.serialize_struct(JWK_NAME, JWK_FIELDS.len())?;
        jwk.serialize_field(KTY, KTY_OKP)?;
        jwk.serialize_field(CRV, CRV_ED25519)?;
        jwk.serialize_field(X, &b64::encode(self.0.0.as_bytes()))?;
        jwk.end()
    }
}

impl<'de> Deserialize<'de> for Jwk {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_struct(JWK_NAME, JWK_FIELDS, JwkVisitor)
    }
}

struct JwkVisitor;

impl<'de> Visitor<'de> for JwkVisitor {
    type Value = Jwk;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(r#"an Ed25519 JWK {"kty":"OKP","crv":"Ed25519","x":...}"#)
    }

    // Only `visit_map`: a JWK written as an array is not a JWK.
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Jwk, A::Error> {
        let mut kty: Option<String> = None;
        let mut crv: Option<String> = None;
        let mut x: Option<String> = None;
        while let Some(key) = map.next_key::<String>()? {
            let slot = match key.as_str() {
                KTY => &mut kty,
                CRV => &mut crv,
                X => &mut x,
                _ => return Err(de::Error::unknown_field(&key, JWK_FIELDS)),
            };
            if slot.is_some() {
                return Err(de::Error::custom(format_args!(
                    "duplicate JWK member `{key}`"
                )));
            }
            *slot = Some(map.next_value()?);
        }
        let kty = kty.ok_or_else(|| de::Error::missing_field(KTY))?;
        let crv = crv.ok_or_else(|| de::Error::missing_field(CRV))?;
        let x = x.ok_or_else(|| de::Error::missing_field(X))?;
        if kty != KTY_OKP {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(&kty),
                &"kty `OKP`",
            ));
        }
        if crv != CRV_ED25519 {
            return Err(de::Error::invalid_value(
                de::Unexpected::Str(&crv),
                &"crv `Ed25519`",
            ));
        }
        let bytes = b64::decode_array::<PUBLIC_KEY_LEN>(&x).ok_or_else(|| {
            de::Error::invalid_value(
                de::Unexpected::Str(&x),
                &"unpadded base64url of exactly 32 bytes",
            )
        })?;
        PublicKey::from_bytes(&bytes)
            .map(Jwk)
            .map_err(de::Error::custom)
    }
}
