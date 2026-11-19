//! Store/Results container: RC4 header + two RC4 sections, each with a fresh keystream (spec §3).
use crate::crypto::Rc4Ks;

/// Per-section cap (spec §4 Robust parsing).
pub const MAX_RECORD: u64 = 16 * 1024 * 1024;
const HDR: usize = 0x3C;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseErr {
    pub file: String,
    pub offset: u32,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct Container {
    pub header: Vec<u8>,
    pub sec1: Vec<u8>,
    pub sec2: Vec<u8>,
    /// Bytes after the declared sections.
    pub trailing: u32,
}

fn err(offset: u32, reason: impl Into<String>) -> ParseErr {
    ParseErr {
        file: String::new(),
        offset,
        reason: reason.into(),
    }
}

pub fn open_container(raw: &[u8], ks: &Rc4Ks) -> Result<Container, ParseErr> {
    if raw.len() as u64 > MAX_RECORD {
        return Err(err(
            0,
            format!(
                "record of {} bytes exceeds the {MAX_RECORD}-byte cap",
                raw.len()
            ),
        ));
    }
    let head = raw.get(..HDR).ok_or_else(|| {
        err(
            0,
            format!(
                "file of {} bytes is shorter than the 0x3C header",
                raw.len()
            ),
        )
    })?;
    let header = ks.crypt(head);
    if header[0..4] != [0xdb, 0xe8, 0xc5, 0x01] {
        return Err(err(
            0,
            "bad header magic (not a Defender history record, or different key)",
        ));
    }
    if header[0x38..0x3C] != [0xdb, 0xe8, 0xc5, 0x02] {
        return Err(err(0x38, "bad header end magic"));
    }
    let len1 = u32::from_le_bytes([header[0x28], header[0x29], header[0x2A], header[0x2B]]) as u64;
    let len2 = u32::from_le_bytes([header[0x2C], header[0x2D], header[0x2E], header[0x2F]]) as u64;
    let file_len = raw.len() as u64;
    let end1 = HDR as u64 + len1;
    if len1 > MAX_RECORD || end1 > file_len {
        return Err(err(
            0x28,
            format!("section 1 length {len1} extends beyond the file ({file_len} bytes) or cap"),
        ));
    }
    let end2 = end1 + len2;
    if len2 > MAX_RECORD || end2 > file_len {
        return Err(err(
            0x2C,
            format!("section 2 length {len2} extends beyond the file ({file_len} bytes) or cap"),
        ));
    }
    Ok(Container {
        sec1: ks.crypt(&raw[HDR..end1 as usize]),
        sec2: ks.crypt(&raw[end1 as usize..end2 as usize]),
        header,
        trailing: (file_len - end2) as u32,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::embedded_key;

    /// Encrypted container built the same way as tests/gen_fixtures.py.
    pub(crate) fn make(sec1: &[u8], sec2: &[u8]) -> Vec<u8> {
        let ks = Rc4Ks::new(&embedded_key());
        let mut h = vec![0u8; HDR];
        h[0..4].copy_from_slice(&[0xdb, 0xe8, 0xc5, 0x01]);
        h[0x28..0x2C].copy_from_slice(&(sec1.len() as u32).to_le_bytes());
        h[0x2C..0x30].copy_from_slice(&(sec2.len() as u32).to_le_bytes());
        h[0x38..0x3C].copy_from_slice(&[0xdb, 0xe8, 0xc5, 0x02]);
        [ks.crypt(&h), ks.crypt(sec1), ks.crypt(sec2)].concat()
    }

    #[test]
    fn whole_record_cap_applies() {
        let ks = Rc4Ks::new(&embedded_key());
        let big = make(&vec![0u8; 9 << 20], &vec![0u8; 9 << 20]);
        assert!(open_container(&big, &ks).is_err());
    }

    #[test]
    fn trailing_bytes_after_sections_reported() {
        let ks = Rc4Ks::new(&embedded_key());
        let mut raw = make(b"", &[4, 0, 0, 0]);
        raw.extend([0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(open_container(&raw, &ks).unwrap().trailing, 4);
    }
}
