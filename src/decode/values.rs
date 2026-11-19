//! Integer, FileRef, GUID, digest, registry and enum decoders (spec §6).
use crate::model::FileRef;

/// Bit-for-bit reinterpretation of an SQLite integer as unsigned.
pub fn as_u64(v: i64) -> u64 {
    v as u64
}

/// NTFS reference from `FileHashes.FileID` (record = low 48 bits, seq = high 16) on volume `VSN`.
pub fn fileref(file_id: i64, vsn: i64) -> FileRef {
    let u = as_u64(file_id);
    FileRef {
        vsn: vsn as u32,
        record: u & 0xFFFF_FFFF_FFFF,
        seq: (u >> 48) as u16,
    }
}

pub fn fmt_fileref(r: &FileRef) -> String {
    format!("{}-{}", r.record, r.seq)
}

pub fn fmt_vsn(v: u32) -> String {
    format!("{:04X}-{:04X}", v >> 16, v & 0xFFFF)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// 16-byte little-endian GUID → `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
pub fn fmt_guid(b: &[u8]) -> Option<String> {
    let b: &[u8; 16] = b.try_into().ok()?;
    let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    let tail: String = b[10..].iter().map(|x| format!("{x:02X}")).collect();
    Some(format!(
        "{{{d1:08X}-{d2:04X}-{d3:04X}-{:02X}{:02X}-{tail}}}",
        b[8], b[9]
    ))
}

/// KNOWNFOLDERID names for the folders Controlled Folder Access protects by default.
pub fn known_folder(guid: &str) -> Option<&'static str> {
    const T: &[(&str, &str)] = &[
        ("{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}", "Desktop"),
        ("{FDD39AD0-238F-46AF-ADB4-6C85480369C7}", "Documents"),
        ("{374DE290-123F-4565-9164-39C4925E467B}", "Downloads"),
        ("{4BD8D571-6D19-48D3-BE97-422220080E43}", "Music"),
        ("{33E28130-4E1E-4676-835A-98395C3BC3BB}", "Pictures"),
        ("{18989B1D-99B5-455B-841C-AB7C74E4DDFC}", "Videos"),
        ("{1777F761-68AD-4D8A-87BD-30B759FA33DD}", "Favorites"),
        ("{C4AA340D-F20F-4863-AFEF-F87EF2E6BA25}", "Public Desktop"),
        ("{ED4824AF-DCE4-45A8-81E2-FC7965083634}", "Public Documents"),
        ("{3214FAB5-9757-4298-BB61-92A9DEAA44FF}", "Public Music"),
        ("{B6EBFB86-6907-413C-9AF7-4FC2ABF07CC5}", "Public Pictures"),
        ("{2400183A-6185-49FB-A2D8-4A392A602BA3}", "Public Videos"),
    ];
    T.iter()
        .find(|(g, _)| g.eq_ignore_ascii_case(guid))
        .map(|(_, n)| *n)
}

pub fn reg_type_name(t: i64) -> String {
    match t {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => return format!("0x{t:X} (unknown)"),
    }
    .to_string()
}

fn utf16z(b: &[u8]) -> Vec<String> {
    let w: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    w.split(|&c| c == 0).map(String::from_utf16_lossy).collect()
}

/// Registry data by type; malformed lengths fall back to hex.
pub fn reg_data(t: i64, b: &[u8]) -> String {
    match (t, b.len()) {
        (4, 4) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]).to_string(),
        (5, 4) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]).to_string(),
        (11, 8) => u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]).to_string(),
        (1 | 2, n) if n % 2 == 0 => utf16z(b).into_iter().next().unwrap_or_default(),
        (7, n) if n % 2 == 0 => utf16z(b)
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" | "),
        _ => hex(b),
    }
}

/// Known enum names; anything else `0x… (unknown)`.
pub fn enum_name(field: &str, v: i64) -> String {
    let known = match (field, v) {
        ("SCANREASON", 2) => Some("on-open"),
        ("SCANREASON", 5) => Some("on-close after write"),
        _ => None,
    };
    known
        .map(str::to_string)
        .unwrap_or_else(|| format!("0x{v:X} (unknown)"))
}

/// `0x120089 = bits 0,3,7,17,20`.
pub fn flag_bits(v: u64) -> String {
    if v == 0 {
        return "0x0".into();
    }
    let bits: Vec<String> = (0..64)
        .filter(|i| v >> i & 1 == 1)
        .map(|i| i.to_string())
        .collect();
    format!("0x{v:X} = bits {}", bits.join(","))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FileRef;

    #[test]
    fn fileref_example() {
        let r = fileref(2533274790530311, -328604643);
        assert_eq!(
            r,
            FileRef {
                vsn: 3966362653,
                record: 134407,
                seq: 9
            }
        );
        assert_eq!(fmt_fileref(&r), "134407-9");
        assert_eq!(fmt_vsn(3966362653), "EC69-E41D");
    }

    #[test]
    fn fileref_negative_bits_preserved() {
        let r = fileref(-1, 0);
        assert_eq!((r.record, r.seq), (0xFFFF_FFFF_FFFF, 0xFFFF));
        assert_eq!(as_u64(-1), u64::MAX);
    }

    #[test]
    fn guid_mixed_endian() {
        let b = [
            0xd0, 0x9a, 0xd3, 0xfd, 0x8f, 0x23, 0xaf, 0x46, 0xad, 0xb4, 0x6c, 0x85, 0x48, 0x03,
            0x69, 0xc7,
        ];
        let g = fmt_guid(&b).unwrap();
        assert_eq!(g, "{FDD39AD0-238F-46AF-ADB4-6C85480369C7}");
        assert_eq!(known_folder(&g), Some("Documents"));
        assert_eq!(fmt_guid(&b[..15]), None);
    }

    #[test]
    fn hex_lower() {
        assert_eq!(hex(&[0xAB, 0x01]), "ab01");
    }

    #[test]
    fn reg_decoding() {
        assert_eq!(reg_type_name(4), "REG_DWORD");
        assert_eq!(reg_type_name(99), "0x63 (unknown)");
        assert_eq!(reg_data(4, &[2, 0, 0, 0]), "2");
        assert_eq!(reg_data(5, &[0, 0, 0, 2]), "2");
        assert_eq!(reg_data(11, &[1, 0, 0, 0, 0, 0, 0, 0]), "1");
        assert_eq!(reg_data(1, &[b'h', 0, b'i', 0, 0, 0]), "hi");
        assert_eq!(reg_data(7, &[b'a', 0, 0, 0, b'b', 0, 0, 0, 0, 0]), "a | b");
        assert_eq!(reg_data(4, &[1, 2]), "0102");
        assert_eq!(reg_data(3, &[0xFF]), "ff");
    }

    #[test]
    fn enum_names() {
        assert_eq!(enum_name("SCANREASON", 2), "on-open");
        assert_eq!(enum_name("SCANREASON", 5), "on-close after write");
        assert_eq!(enum_name("SCANREASON", 9), "0x9 (unknown)");
        assert_eq!(enum_name("RegOperation", 21), "0x15 (unknown)");
    }

    #[test]
    fn flag_bit_listing() {
        assert_eq!(flag_bits(0x120089), "0x120089 = bits 0,3,7,17,20");
        assert_eq!(flag_bits(0), "0x0");
    }
}
