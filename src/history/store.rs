//! Store property bags (spec §3).
use super::container::{MAX_RECORD, ParseErr, open_container};
use crate::crypto::{Key, Rc4Ks};
use crate::evidence::{Input, read_input};
use crate::model::Ft;
use std::path::Path;

#[derive(Clone, Debug, PartialEq)]
pub enum PropVal {
    U32(u32),
    U64(u64),
    Bool(u8),
    Str(String),
    /// Type 9: fixed 8 bytes. Every other type besides 3–6: u32 byte length + bytes (observed 7, 8).
    Bytes {
        typ: u32,
        data: Vec<u8>,
    },
}

#[derive(Clone, Debug)]
pub struct Prop {
    pub name: String,
    pub val: PropVal,
    /// Offset of the property's name-length field within decrypted section 2.
    pub offset: u32,
    pub lossy_utf16: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreKind {
    Context,
    Amsi,
    Other,
}

#[derive(Clone, Debug)]
pub struct StoreRec {
    pub file: String,
    pub kind: StoreKind,
    pub props: Vec<Prop>,
    /// Bytes after the bag's declared length.
    pub trailing: u32,
    /// Bytes after the container's declared sections.
    pub container_trailing: u32,
}

impl StoreRec {
    pub fn get(&self, name: &str) -> Option<&PropVal> {
        self.props.iter().find(|p| p.name == name).map(|p| &p.val)
    }

    pub fn get_str(&self, name: &str) -> Option<&str> {
        match self.get(name) {
            Some(PropVal::Str(s)) => Some(s),
            _ => None,
        }
    }

    /// `CONTEXT_DATA_PROCESS_PPID` = `pid:<N>,ProcessStart:<FILETIME>` of the acting process.
    pub fn ppid(&self) -> Option<(u32, Ft)> {
        parse_pid_start(self.get_str("CONTEXT_DATA_PROCESS_PPID")?)
    }
}

/// `pid:<N>,ProcessStart:<FT>` (anything after the FILETIME digits is ignored).
pub fn parse_pid_start(s: &str) -> Option<(u32, Ft)> {
    let rest = s.trim().strip_prefix("pid:")?;
    let (pid, rest) = rest.split_once(',')?;
    let ft = rest.strip_prefix("ProcessStart:")?;
    let digits: String = ft.chars().take_while(|c| c.is_ascii_digit()).collect();
    Some((pid.parse().ok()?, digits.parse().ok()?))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o.checked_add(4)?)
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}

fn utf16(b: &[u8]) -> (String, bool) {
    let w: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let (s, lossy) = match String::from_utf16(&w) {
        Ok(s) => (s, b.len() % 2 != 0),
        Err(_) => (String::from_utf16_lossy(&w), true),
    };
    (s.trim_end_matches('\0').to_string(), lossy)
}

/// Parses a decrypted section 2. Errors carry the offset of the field that could not be framed.
pub fn parse_bag(b: &[u8]) -> Result<(Vec<Prop>, u32), (u32, String)> {
    let total = u32_at(b, 0).ok_or((0, "bag shorter than its length field".to_string()))? as usize;
    if total < 4 || total > b.len() {
        return Err((0, format!("bag length {total} outside 4..={}", b.len())));
    }
    let mut props = Vec::new();
    let mut off = 4usize;
    while off < total {
        let start = off;
        let at = |o: usize, what: &str| {
            (
                o as u32,
                format!("{what} at offset {o:#x} extends beyond the bag"),
            )
        };
        let nlen = u32_at(b, off).ok_or_else(|| at(off, "name length"))? as usize;
        if nlen == 0 || nlen > 1024 || nlen % 2 != 0 {
            return Err((
                off as u32,
                format!("implausible name length {nlen} at offset {off:#x}"),
            ));
        }
        off += 4;
        let nb = b
            .get(off..off + nlen)
            .filter(|_| off + nlen <= total)
            .ok_or_else(|| at(off, "name"))?;
        let (name, mut lossy) = utf16(nb);
        off += nlen;
        let typ = u32_at(b, off)
            .filter(|_| off + 4 <= total)
            .ok_or_else(|| at(off, "type"))?;
        off += 4;
        let fixed = |n: usize| b.get(off..off + n).filter(|_| off + n <= total);
        let val = match typ {
            3 => {
                let v = fixed(4).ok_or_else(|| at(off, "u32 value"))?;
                off += 4;
                PropVal::U32(u32::from_le_bytes([v[0], v[1], v[2], v[3]]))
            }
            4 => {
                let v = fixed(8).ok_or_else(|| at(off, "u64 value"))?;
                off += 8;
                PropVal::U64(u64::from_le_bytes([
                    v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7],
                ]))
            }
            5 => {
                let v = fixed(1).ok_or_else(|| at(off, "bool value"))?;
                off += 1;
                PropVal::Bool(v[0])
            }
            9 => {
                // Fixed 8 bytes (validated on 84 real records; all zero so far). Not length-prefixed.
                let v = fixed(8).ok_or_else(|| at(off, "type-9 value"))?;
                off += 8;
                PropVal::Bytes {
                    typ,
                    data: v.to_vec(),
                }
            }
            _ => {
                let n = u32_at(b, off)
                    .filter(|_| off + 4 <= total)
                    .ok_or_else(|| at(off, "value length"))? as usize;
                off += 4;
                if n as u64 > MAX_RECORD {
                    return Err((off as u32 - 4, format!("value length {n} exceeds cap")));
                }
                let v = b
                    .get(off..off + n)
                    .filter(|_| off + n <= total)
                    .ok_or_else(|| at(off, "value"))?;
                off += n;
                if typ == 6 {
                    let (s, l) = utf16(v);
                    lossy |= l;
                    PropVal::Str(s)
                } else {
                    PropVal::Bytes {
                        typ,
                        data: v.to_vec(),
                    }
                }
            }
        };
        props.push(Prop {
            name,
            val,
            offset: start as u32,
            lossy_utf16: lossy,
        });
    }
    Ok((props, (b.len() - total) as u32))
}

fn kind_of(props: &[Prop]) -> StoreKind {
    if props.iter().any(|p| p.name == "AMSISession") {
        StoreKind::Amsi
    } else if props.iter().any(|p| p.name.starts_with("CONTEXT_DATA")) {
        StoreKind::Context
    } else {
        StoreKind::Other
    }
}

/// Regular files in `dir`, sorted by name, plus errors for anything that could not be enumerated.
/// A missing directory is not an error (history is optional).
pub(crate) fn files_in(
    dir: &Path,
    label: &str,
) -> (Vec<(String, std::path::PathBuf)>, Vec<ParseErr>) {
    let mut errs = Vec::new();
    let e = |reason: String| ParseErr {
        file: label.to_string(),
        offset: 0,
        reason,
    };
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => return (Vec::new(), errs),
        Err(x) => {
            return (
                Vec::new(),
                vec![e(format!("cannot list {}: {x}", dir.display()))],
            );
        }
    };
    let mut v = Vec::new();
    for ent in rd {
        match ent.and_then(|en| en.file_type().map(|t| (en, t))) {
            Ok((en, t)) if t.is_file() => {
                v.push((en.file_name().to_string_lossy().into_owned(), en.path()))
            }
            Ok(_) => {}
            Err(x) => errs.push(e(format!("cannot read an entry of {}: {x}", dir.display()))),
        }
    }
    v.sort();
    (v, errs)
}

pub fn load_store(dir: &Path, key: &Key) -> (Vec<StoreRec>, Vec<ParseErr>, Vec<Input>) {
    let ks = Rc4Ks::new(key);
    let (mut recs, mut inputs) = (Vec::new(), Vec::new());
    let (files, mut errs) = files_in(dir, "Store");
    for (name, path) in files {
        let input = match read_input(&path, MAX_RECORD) {
            Ok(i) => i,
            Err(e) => {
                errs.push(ParseErr {
                    file: name,
                    offset: 0,
                    reason: e,
                });
                continue;
            }
        };
        let parsed = open_container(&input.bytes, &ks).and_then(|c| {
            parse_bag(&c.sec2)
                .map(|(p, t)| (p, t, c.trailing))
                .map_err(|(o, r)| ParseErr {
                    file: String::new(),
                    offset: o,
                    reason: format!("section 2: {r}"),
                })
        });
        match parsed {
            Ok((props, trailing, container_trailing)) => recs.push(StoreRec {
                file: name,
                kind: kind_of(&props),
                props,
                trailing,
                container_trailing,
            }),
            Err(mut e) => {
                e.file = name;
                errs.push(e);
            }
        }
        inputs.push(input);
    }
    (recs, errs, inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::embedded_key;
    use std::path::PathBuf;

    fn hist() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/history")
    }

    fn load() -> (Vec<StoreRec>, Vec<super::super::container::ParseErr>) {
        let (recs, errs, _) = load_store(&hist().join("Store"), &embedded_key());
        (recs, errs)
    }

    fn rec(name: &str) -> StoreRec {
        load().0.into_iter().find(|r| r.file == name).unwrap()
    }

    #[test]
    fn store_context_ppid() {
        let r = rec("0123456789ABCDEF0123456789ABCDEF");
        assert_eq!(r.kind, StoreKind::Context);
        assert_eq!(r.ppid(), Some((4120, 134369015368153546)));
        assert!(
            matches!(r.get("CONTEXT_DATA_PROCESSNAME"), Some(PropVal::Str(s)) if s == "curl.exe")
        );
    }

    #[test]
    fn store_type9_fixed8_then_next_prop_aligned() {
        let r = rec("0123456789ABCDEF0123456789ABCDEF");
        assert_eq!(r.props.len(), 12);
        assert!(
            matches!(r.get("CONTEXT_DATA_AMSI_UAC_REQUEST_CONTEXT"), Some(PropVal::Bytes { typ: 9, data }) if data == &[0u8; 8])
        );
        assert!(matches!(
            r.get("CONTEXT_DATA_DESIREDACCESS"),
            Some(PropVal::U32(0x120089))
        ));
        assert_eq!(r.trailing, 0);
    }

    #[test]
    fn store_amsi_kind() {
        let r = rec("11111111111111111111111111111111");
        assert_eq!(r.kind, StoreKind::Amsi);
        assert!(
            matches!(r.get("AMSIPidCreationTime"), Some(PropVal::U64(t)) if *t == 134369015368153546 - 1_000_000_000)
        );
    }

    #[test]
    fn store_unknown_type_with_len_continues() {
        let r = rec("22222222222222222222222222222222");
        assert!(
            matches!(r.get("Weird"), Some(PropVal::Bytes { typ: 12, data }) if data == &[1, 2, 3, 4])
        );
        assert!(
            matches!(r.get("CONTEXT_DATA_FILENAME"), Some(PropVal::Str(s)) if s == "after.txt")
        );
    }

    #[test]
    fn store_truncated_reports_offset() {
        let (recs, errs) = load();
        assert_eq!(recs.len(), 3);
        let e = errs
            .iter()
            .find(|e| e.file == "33333333333333333333333333333333")
            .unwrap();
        assert!(e.reason.contains("beyond"), "{}", e.reason);
        assert_eq!(e.offset, 0x2C);
    }

    #[test]
    fn oversized_len_rejected_without_alloc() {
        let (_, errs) = load();
        assert!(
            errs.iter()
                .any(|e| e.file == "44444444444444444444444444444444")
        );
    }

    /// Local evidence only (never committed): every real Store record parses without desync.
    #[test]
    #[ignore]
    fn real_store_vss9_parses_all() {
        let d = std::path::Path::new(r"C:\dfir_research\copies\vss9\Defender_History\Store");
        let (recs, errs, _) = load_store(d, &embedded_key());
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(recs.len(), 84);
        assert!(
            recs.iter()
                .filter(|r| r.kind == StoreKind::Context)
                .all(|r| r.get("Id").is_some()),
            "tail property Id missing"
        );
        assert!(recs.iter().all(|r| r.trailing == 0));
        assert_eq!(recs.iter().filter(|r| r.kind == StoreKind::Amsi).count(), 4);
    }

    #[test]
    fn unreadable_store_dir_is_an_error_not_empty() {
        let d = crate::evidence::tests::tmpdir("store_notdir");
        std::fs::write(d.join("Store"), b"not a directory").unwrap();
        let (recs, errs, _) = load_store(&d.join("Store"), &embedded_key());
        assert!(recs.is_empty());
        assert_eq!(errs.len(), 1);
        let (_, errs, _) = load_store(&d.join("Missing"), &embedded_key());
        assert!(errs.is_empty());
    }

    #[test]
    fn bag_with_huge_name_len_is_error_not_panic() {
        let mut b = 8u32.to_le_bytes().to_vec();
        b.extend(0xFFFF_FFF0u32.to_le_bytes());
        assert!(parse_bag(&b).is_err());
    }
}
