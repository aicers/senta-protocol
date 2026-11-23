//! The `hardware_hash` vector file: the hardware identifier hash of a
//! machine identifier, computed here with HMAC-SHA256 directly rather than
//! by the crate's function.

use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;

use crate::fixtures::{b64, bytes32, hw_salt};
use crate::model::{
    Category, FORMAT_VERSION, HardwareCase, HardwareExpected, HardwareInput, MachineIdKind,
    VectorFile,
};

/// What the hash is computed over ahead of `hw_salt`.
const CONTEXT: &[u8] = b"clumit-endpoint";

/// The 16 bytes of the first machine identifier.
const MACHINE: [u8; 16] = [
    0x8f, 0x14, 0xe4, 0x5f, 0xce, 0xea, 0x16, 0x7a, 0x5a, 0x36, 0xde, 0xdd, 0x4b, 0xea, 0x25, 0x43,
];

/// The 16 bytes of the second machine identifier.
const OTHER_MACHINE: [u8; 16] = [
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

/// HMAC-SHA256 keyed with the 16 bytes, over `clumit-endpoint` ‖ `hw_salt`.
fn expected_hash(machine: &[u8; 16], salt: &[u8; 32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(machine).expect("HMAC takes a key of any length");
    mac.update(CONTEXT);
    mac.update(salt);
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The `8-4-4-4-12` notation of 16 bytes in the order given.
fn guid(bytes: &[u8; 16]) -> String {
    let text = hex(bytes);
    let group = |start: usize, end: usize| text.get(start..end).expect("32 digits").to_owned();
    [
        group(0, 8),
        group(8, 12),
        group(12, 16),
        group(16, 20),
        group(20, 32),
    ]
    .join("-")
}

fn case(
    name: &str,
    description: &str,
    kind: MachineIdKind,
    machine_id: String,
    machine: &[u8; 16],
    salt: &[u8; 32],
) -> HardwareCase {
    HardwareCase {
        name: name.to_owned(),
        description: description.to_owned(),
        input: HardwareInput {
            machine_id_kind: kind,
            machine_id,
            hw_salt: b64(salt),
        },
        expected: HardwareExpected {
            machine_id_hash: b64(&expected_hash(machine, salt)),
        },
    }
}

pub fn file() -> VectorFile<HardwareCase> {
    let salt = hw_salt();
    let other_salt = bytes32("other hw_salt");
    let linux = hex(&MACHINE);
    let windows = guid(&MACHINE);
    let same = "the same 16 bytes as linux_lowercase, so the same hash";
    let cases = vec![
        case(
            "linux_lowercase",
            "A Linux machine-id in lowercase digits.",
            MachineIdKind::Linux,
            linux.clone(),
            &MACHINE,
            &salt,
        ),
        case(
            "linux_uppercase",
            &format!("The same machine-id in uppercase digits: {same}."),
            MachineIdKind::Linux,
            linux.to_uppercase(),
            &MACHINE,
            &salt,
        ),
        case(
            "windows_lowercase",
            &format!("A Windows MachineGuid of {same}, lowercase, without braces."),
            MachineIdKind::Windows,
            windows.clone(),
            &MACHINE,
            &salt,
        ),
        case(
            "windows_uppercase",
            &format!("A Windows MachineGuid of {same}, uppercase, without braces."),
            MachineIdKind::Windows,
            windows.to_uppercase(),
            &MACHINE,
            &salt,
        ),
        case(
            "windows_braces_lowercase",
            &format!("A Windows MachineGuid of {same}, lowercase, in braces."),
            MachineIdKind::Windows,
            format!("{{{windows}}}"),
            &MACHINE,
            &salt,
        ),
        case(
            "windows_braces_uppercase",
            &format!("A Windows MachineGuid of {same}, uppercase, in braces."),
            MachineIdKind::Windows,
            format!("{{{}}}", windows.to_uppercase()),
            &MACHINE,
            &salt,
        ),
        case(
            "linux_other_machine_other_salt",
            "Another machine-id with another hw_salt.",
            MachineIdKind::Linux,
            hex(&OTHER_MACHINE),
            &OTHER_MACHINE,
            &other_salt,
        ),
        case(
            "windows_other_machine_other_salt",
            "The MachineGuid of the same bytes as linux_other_machine_other_salt, with the same hw_salt.",
            MachineIdKind::Windows,
            guid(&OTHER_MACHINE),
            &OTHER_MACHINE,
            &other_salt,
        ),
    ];
    VectorFile {
        format_version: FORMAT_VERSION,
        category: Category::HardwareHash,
        keys: Vec::new(),
        cases,
    }
}
