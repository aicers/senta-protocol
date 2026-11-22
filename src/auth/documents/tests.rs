//! Unit tests of the document forms and of the strict reading of contents.
//!
//! These run without the `test-util` feature too, so with serde_json's
//! `arbitrary_precision` feature on as well.

use std::cmp::Ordering;

use jiff::{SignedDuration, Timestamp};
use serde_json::json;

use super::*;
use crate::auth::jws::test_util::TestKey;
use crate::auth::jws::{KeyKind, KeyLookup};
use crate::auth::tls;

const ENDPOINT: &str = "0f8fad5b-d9cb-469f-a165-70867728950e";
const KID: &str = "endpoint-0f8fad5b-d9cb-469f-a165-70867728950e:1";

#[test]
fn integers_hold_their_range() {
    assert_eq!(Integer::new(0).map(Integer::get), Some(0));
    assert_eq!(Integer::new(strict::MAX_INTEGER), Some(Integer::MAX));
    assert_eq!(Integer::new(strict::MAX_INTEGER + 1), None);
    assert_eq!(Integer::from(u32::MAX).get(), u64::from(u32::MAX));
    assert_eq!(PositiveInteger::new(0), None);
    assert_eq!(PositiveInteger::new(1).map(PositiveInteger::get), Some(1));
    assert_eq!(PositiveInteger::new(strict::MAX_INTEGER + 1), None);
}

#[test]
fn integers_parse_strictly() {
    #[derive(Debug, serde::Deserialize)]
    struct Content {
        n: Integer,
        p: PositiveInteger,
        e: Vec<u16>,
    }
    let parsed: Content =
        strict::from_slice(br#"{"n":9007199254740991,"p":1,"e":[0,65535]}"#).unwrap();
    assert_eq!(
        (parsed.n, parsed.p.get(), parsed.e),
        (Integer::MAX, 1, vec![0, 65535])
    );
    for bad in [
        r#"{"n":9007199254740992,"p":1,"e":[]}"#,
        r#"{"n":-1,"p":1,"e":[]}"#,
        r#"{"n":1.0,"p":1,"e":[]}"#,
        r#"{"n":1e2,"p":1,"e":[]}"#,
        r#"{"n":100000000000000000000,"p":1,"e":[]}"#,
        r#"{"n":0,"p":0,"e":[]}"#,
        r#"{"n":0,"p":1,"e":[65536]}"#,
        r#"{"n":"0","p":1,"e":[]}"#,
    ] {
        assert!(
            strict::from_slice::<Content>(bad.as_bytes()).is_err(),
            "{bad}"
        );
    }
}

#[test]
fn string_forms_parse_their_grammar() {
    assert!(InstallId::parse("!~x/y").is_some());
    for bad in ["", "a:b", "a b", "é", "\u{7f}"] {
        assert!(InstallId::parse(bad).is_none(), "{bad:?}");
    }

    let name = CustomerKeyName::parse(&format!("endpoint-{ENDPOINT}")).unwrap();
    assert_eq!(name.to_string(), format!("endpoint-{ENDPOINT}"));
    assert_eq!(name.endpoint_id().get().to_string(), ENDPOINT);
    assert_eq!(CustomerKeyName::from_endpoint_id(name.endpoint_id()), name);
    for bad in [
        ENDPOINT.to_owned(),
        format!("endpoint-{}", ENDPOINT.to_uppercase()),
        format!("endpoint-{ENDPOINT}:1"),
        format!("recovery-{ENDPOINT}"),
    ] {
        assert!(CustomerKeyName::parse(&bad).is_none(), "{bad}");
    }

    let kid = CustomerKid::parse(KID).unwrap();
    assert_eq!(kid.as_str(), KID);
    assert_eq!(kid.as_kid().kind(), KeyKind::Customer);
    assert!(CustomerKid::parse("recovery-a:1").is_none());
    assert!(CustomerKid::parse("endpoint-x:1").is_none());

    for good in ["1", "9", "10", "65535"] {
        assert_eq!(KindNumber::parse(good).unwrap().to_string(), good);
    }
    for bad in ["", "0", "01", "65536", "+1", "-1", " 1", "1 ", "x"] {
        assert!(KindNumber::parse(bad).is_none(), "{bad:?}");
    }
    assert!(KindNumber::new(0).is_none());

    assert!(NonEmptyString::new("").is_none());
    assert!(JwsText::new("").is_none());
    assert_eq!(NonEmptyString::new("x").unwrap().as_str(), "x");

    let url = AbsoluteUrl::parse("HTTPS://Dist.Example").unwrap();
    assert_eq!(url.as_str(), "https://dist.example/");
    for bad in [
        "",
        "/x",
        "x",
        " https://a/",
        "https://a/\t",
        "https://a/\r\n",
    ] {
        assert!(AbsoluteUrl::parse(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn dns_names_are_a_subset_of_what_rustls_accepts() {
    let good = [
        "a",
        "localhost",
        "1.node.example",
        "A-1.b2.example",
        "x--y.example",
    ];
    for name in good {
        assert!(DnsName::parse(name).is_some(), "{name}");
        assert!(tls::expected_server_name(name).is_ok(), "{name}");
    }
    let bad = [
        "", "1.2.3.4", "::1", "[::1]", "a.", ".a", "a..b", "-a", "a-", "a_b", "a.1", "a:1", "a b",
    ];
    for name in bad {
        assert!(DnsName::parse(name).is_none(), "{name:?}");
    }
    assert!(DnsName::parse(&"a".repeat(63)).is_some());
    assert!(DnsName::parse(&"a".repeat(64)).is_none());
}

#[test]
fn addresses_round_trip_through_their_display() {
    for (text, written) in [
        ("a.example:443", "a.example:443"),
        ("10.1.2.3:1", "10.1.2.3:1"),
        ("[0::1]:65535", "[::1]:65535"),
    ] {
        let address = Address::parse(text).unwrap();
        assert_eq!(address.to_string(), written);
        assert_eq!(Address::parse(written), Some(address));
    }
    for bad in [
        "a.example",
        "a.example:0",
        "a.example:01",
        "::1:443",
        "[::1]",
        "1.2.3:4",
    ] {
        assert!(Address::parse(bad).is_none(), "{bad}");
    }
}

#[test]
fn pem_follows_the_tls_rule() {
    let block = "-----BEGIN CERTIFICATE-----\nMAMCAQE=\n-----END CERTIFICATE-----\n";
    assert!(CertificatePem::parse(block).is_some());
    assert!(CertificatePem::parse(&format!("notes\n{block}{block}more")).is_some());
    assert!(CertificatePem::parse(&block.replace('\n', "\r")).is_some());
    for bad in [
        String::new(),
        "text".to_owned(),
        block.replace("CERTIFICATE", "PUBLIC KEY"),
        block.replace("-----END CERTIFICATE-----\n", ""),
        format!("{block}-----END CERTIFICATE-----\n"),
        block.replace("MAMCAQE=", "!!"),
    ] {
        assert!(CertificatePem::parse(&bad).is_none(), "{bad:?}");
        assert_eq!(
            tls::pem_certificates(&bad).is_err(),
            CertificatePem::parse(&bad).is_none()
        );
    }
}

#[test]
fn semver_precedence_ignores_build_metadata() {
    let parse = |text| SemVer::parse(text).unwrap();
    assert_eq!(
        parse("1.0.0-rc.1").cmp_precedence(&parse("1.0.0")),
        Ordering::Less
    );
    assert_eq!(
        parse("1.0.0+a").cmp_precedence(&parse("1.0.0+b")),
        Ordering::Equal
    );
    assert_ne!(parse("1.0.0+a"), parse("1.0.0+b"));
    assert!(SemVer::parse("v1.0.0").is_none());
}

struct OneKey(TestKey);

impl KeySource for OneKey {
    fn find_key(&self, kid: &Kid, _: &[KeyKind]) -> KeyLookup {
        if kid.as_str() == KID {
            KeyLookup::Found {
                key: self.0.public_key(),
                kind: KeyKind::Customer,
            }
        } else {
            KeyLookup::Unknown
        }
    }
}

#[test]
fn verification_parses_only_after_the_signature() {
    let key = TestKey::from_seed(&[1; 32]);
    let source = OneKey(TestKey::from_seed(&[1; 32]));
    let content = json!({"token_id": ENDPOINT});
    let payload = serde_json::to_vec(&content).unwrap();

    let document = verify_enroll(&key.sign(Typ::Enroll, KID, &payload), &source).unwrap();
    assert_eq!(document.content().token_id.get().to_string(), ENDPOINT);
    assert_eq!(document.content().expires_at, None);

    let forged = TestKey::from_seed(&[2; 32]).sign(Typ::Enroll, KID, b"{\"x\":1}");
    let error = verify_enroll(&forged, &source).unwrap_err();
    assert_eq!(error.result(), DocumentResult::BadSignature);

    let bad = key.sign(Typ::Enroll, KID, b"{\"token_id\":1}");
    let error = verify_enroll(&bad, &source).unwrap_err();
    assert_eq!(error.result(), DocumentResult::SchemaError);
    assert_eq!(
        error.schema_error().map(SchemaError::path),
        Some("$.token_id")
    );
    assert_eq!(error.header().map(HeaderDiagnostics::kid), Some(KID));
}

#[test]
fn window_bounds_are_strict() {
    let issued: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
    let expires = issued + MAX_COMMAND_LIFETIME;
    let nano = SignedDuration::from_nanos(1);
    let check = |now| check_validity_window(now, issued, expires, MAX_COMMAND_LIFETIME);
    assert_eq!(check(issued - CLOCK_SKEW), Ok(()));
    assert_eq!(
        check(issued - CLOCK_SKEW - nano),
        Err(DocumentResult::NotYetValid)
    );
    assert_eq!(check(expires + CLOCK_SKEW), Ok(()));
    assert_eq!(
        check(expires + CLOCK_SKEW + nano),
        Err(DocumentResult::Expired)
    );
    assert_eq!(
        check_validity_window(issued, issued, expires + nano, MAX_COMMAND_LIFETIME),
        Err(DocumentResult::Expired)
    );
}
