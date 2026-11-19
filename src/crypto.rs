//! RC4 with Defender's fixed engine key (spec §3).

const KEY_HEX: &str = concat!(
    "1e87781b8dbaa844ce69702c0c78b786a3f623b738f5edf9af83530fb3fc54faa21eb9cf1331fd0f0da954f687cb9e18279697900e53fb317c9cb",
    "ce48e23d05371ecc15951b8f3649d7ca33ed68dc9047e82c9baad9799d0d458cb847ca9ffbe3c8a775233557dde13a8b14087cc1bc8f10f6ecdd0",
    "83a959cff84a9d1d50755e3e191818af23e2293558766d2c07e25712b2ca0b535ed8f6c56ce73d24bdd0291771861a54b4c285a9a3db7aca6d224",
    "aeacd621db9f2a22ed1e9e11d75bed7dc0ecb0a8e68a2ff1263408dc808dffd164b116774cd0b9b8d05411ed6262e429ba495676b8398db2f35d3",
    "c1b9ced52636f2765e1a95cb7ca4c3ddabddbff38253"
);

/// SQLite file magic; RC4 of it forms page-1 bytes 0..16 of an encrypted DB.
pub const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// A 256-byte RC4 key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Key(pub [u8; 256]);

/// Defender's fixed mpengine key (public; also protects quarantine files).
pub fn embedded_key() -> Key {
    let mut k = [0u8; 256];
    for (i, b) in k.iter_mut().enumerate() {
        *b = u8::from_str_radix(&KEY_HEX[i * 2..i * 2 + 2], 16).unwrap_or(0);
    }
    Key(k)
}

/// RC4 key schedule; every `crypt`/`keystream` call restarts the keystream at byte 0.
#[derive(Clone)]
pub struct Rc4Ks {
    s: [u8; 256],
}

impl Rc4Ks {
    pub fn new(k: &Key) -> Self {
        Self::from_bytes(&k.0)
    }

    /// Any non-empty key length (an empty key is treated as a single zero byte).
    pub fn from_bytes(k: &[u8]) -> Self {
        let k: &[u8] = if k.is_empty() { &[0] } else { k };
        let mut s = [0u8; 256];
        for (i, v) in s.iter_mut().enumerate() {
            *v = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(k[i % k.len()]);
            s.swap(i, j as usize);
        }
        Rc4Ks { s }
    }

    pub fn keystream(&self, n: usize) -> Vec<u8> {
        let mut s = self.s;
        let (mut i, mut j) = (0u8, 0u8);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            i = i.wrapping_add(1);
            j = j.wrapping_add(s[i as usize]);
            s.swap(i as usize, j as usize);
            out.push(s[s[i as usize].wrapping_add(s[j as usize]) as usize]);
        }
        out
    }

    pub fn crypt(&self, data: &[u8]) -> Vec<u8> {
        let ks = self.keystream(data.len());
        data.iter().zip(ks).map(|(a, b)| a ^ b).collect()
    }
}

/// True when page-1 bytes 0..16 decrypt to the SQLite magic under `k`.
pub fn key_matches(k: &Key, page1: &[u8]) -> bool {
    match page1.get(..16) {
        Some(head) => Rc4Ks::new(k).crypt(head) == SQLITE_MAGIC,
        None => false,
    }
}

struct Section {
    va: u64,
    vsize: u64,
    raw: u64,
    rsize: u64,
}

/// PE section table, or `None` for a flat buffer (RVA == file offset).
fn pe_sections(b: &[u8]) -> Option<Vec<Section>> {
    let rd16 = |o: usize| {
        b.get(o..o + 2)
            .map(|x| u16::from_le_bytes([x[0], x[1]]) as u64)
    };
    let rd32 = |o: usize| {
        b.get(o..o + 4)
            .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as u64)
    };
    if b.get(..2)? != b"MZ" {
        return None;
    }
    let pe = rd32(0x3C)? as usize;
    if b.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let nsec = rd16(pe + 6)? as usize;
    let opt = rd16(pe + 20)? as usize;
    let table = pe.checked_add(24)?.checked_add(opt)?;
    let mut v = Vec::new();
    for i in 0..nsec.min(96) {
        let o = table + i * 40;
        v.push(Section {
            vsize: rd32(o + 8)?,
            va: rd32(o + 12)?,
            rsize: rd32(o + 16)?,
            raw: rd32(o + 20)?,
        });
    }
    Some(v)
}

fn off_to_rva(secs: &Option<Vec<Section>>, off: u64) -> Option<u64> {
    match secs {
        None => Some(off),
        Some(s) => s
            .iter()
            .find(|x| off >= x.raw && off < x.raw + x.rsize)
            .map(|x| off - x.raw + x.va),
    }
}

fn rva_to_off(secs: &Option<Vec<Section>>, rva: u64) -> Option<u64> {
    match secs {
        None => Some(rva),
        Some(s) => s
            .iter()
            .find(|x| rva >= x.va && rva < x.va + x.vsize.max(x.rsize))
            .map(|x| rva - x.va + x.raw)
            .filter(|o| *o < s.iter().map(|x| x.raw + x.rsize).max().unwrap_or(0)),
    }
}

/// Search `mpengine.dll` bytes for `mov r8d,100h` followed (within 16 bytes) by a RIP-relative `lea`
/// whose target is a 256-byte key that decrypts `page1`.
pub fn find_key(dll: &[u8], page1: &[u8]) -> Option<Key> {
    const MOV: [u8; 6] = [0x41, 0xB8, 0x00, 0x01, 0x00, 0x00];
    const LEAS: [[u8; 3]; 3] = [[0x48, 0x8D, 0x15], [0x4C, 0x8D, 0x05], [0x48, 0x8D, 0x0D]];
    let secs = pe_sections(dll);
    let mut i = 0usize;
    while let Some(pos) = dll
        .get(i..)
        .and_then(|w| w.windows(6).position(|x| x == MOV))
    {
        let m = i + pos;
        for d in 6..=16usize {
            let l = m + d;
            let Some(op) = dll.get(l..l + 3) else { break };
            if !LEAS.iter().any(|x| x == op) {
                continue;
            }
            let Some(r) = dll.get(l + 3..l + 7) else {
                break;
            };
            let rel = i32::from_le_bytes([r[0], r[1], r[2], r[3]]) as i64;
            let Some(instr_rva) = off_to_rva(&secs, l as u64) else {
                continue;
            };
            let target = instr_rva as i64 + 7 + rel;
            if target < 0 {
                continue;
            }
            let Some(off) = rva_to_off(&secs, target as u64) else {
                continue;
            };
            let off = off as usize;
            if let Some(kb) = dll.get(off..off + 256) {
                let mut k = [0u8; 256];
                k.copy_from_slice(kb);
                let key = Key(k);
                if key_matches(&key, page1) {
                    return Some(key);
                }
            }
        }
        i = m + 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn page1(variant: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(variant)
            .join("mpenginedb.db");
        std::fs::read(p).unwrap()[..4096].to_vec()
    }

    #[test]
    fn rc4_known_vector() {
        assert_eq!(
            hex(&Rc4Ks::from_bytes(b"Key").crypt(b"Plaintext")),
            "bbf316e8d940af0ad3"
        );
    }

    #[test]
    fn keystream_restarts_per_call() {
        let k = Rc4Ks::new(&embedded_key());
        assert_eq!(k.crypt(&[0u8; 8]), k.crypt(&[0u8; 8]));
    }

    #[test]
    fn embedded_key_decrypts_fixture_page1() {
        assert!(key_matches(&embedded_key(), &page1("multi_commit")));
        assert!(!key_matches(&Key([7u8; 256]), &page1("multi_commit")));
    }

    #[test]
    fn find_key_in_synthetic_dll() {
        let key = embedded_key();
        let mut dll = vec![0x90u8; 0x200];
        let instr = 0x40usize; // mov r8d,100h ; lea rdx,[rip+rel32]
        dll[instr..instr + 6].copy_from_slice(&[0x41, 0xB8, 0x00, 0x01, 0x00, 0x00]);
        dll[instr + 6..instr + 9].copy_from_slice(&[0x48, 0x8D, 0x15]);
        let key_off = 0x100usize;
        let rel = (key_off as i64 - (instr as i64 + 6 + 7)) as i32;
        dll[instr + 9..instr + 13].copy_from_slice(&rel.to_le_bytes());
        dll.extend(std::iter::repeat_n(0u8, 0x200));
        dll[key_off..key_off + 256].copy_from_slice(&key.0);
        let p1 = page1("multi_commit");
        assert_eq!(find_key(&dll, &p1).map(|k| k.0), Some(key.0));
        let mut no = dll.clone();
        no[key_off..key_off + 256].fill(0);
        assert!(find_key(&no, &p1).is_none());
    }
}
