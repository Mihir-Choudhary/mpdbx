//! DB page decryption and WAL replay (spec §3).
pub mod wal;

use crate::crypto::{Key, Rc4Ks, SQLITE_MAGIC, key_matches};
pub use wal::{WalReport, WalStop};

/// Decrypted page images: the main file alone, and main file + committed WAL frames.
#[derive(Clone, Debug)]
pub struct Images {
    pub db_only: Vec<u8>,
    pub merged: Vec<u8>,
    pub page_size: u32,
    /// Original header bytes 18–19 (2,2 = WAL mode); left untouched in both images.
    pub header_18_19: [u8; 2],
    pub encrypted: bool,
    pub wal: WalReport,
    pub notes: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PagerError {
    NotEncryptedOrWrongKey,
    BadPageSize(u32),
    Empty,
}

/// Decrypts one page. `first` selects the page-1 rule (magic | plaintext 16..24 | RC4 from 24).
pub(crate) struct PageCodec {
    ks: Rc4Ks,
    full: Vec<u8>,
    encrypted: bool,
}

impl PageCodec {
    pub(crate) fn new(key: &Key, page_size: usize, encrypted: bool) -> Self {
        let ks = Rc4Ks::new(key);
        let full = if encrypted {
            ks.keystream(page_size)
        } else {
            Vec::new()
        };
        PageCodec {
            ks,
            full,
            encrypted,
        }
    }

    pub(crate) fn decrypt(&self, page: &[u8], first: bool) -> Vec<u8> {
        if !self.encrypted {
            return page.to_vec();
        }
        if first {
            let mut out = Vec::with_capacity(page.len());
            out.extend_from_slice(SQLITE_MAGIC);
            out.extend_from_slice(page.get(16..24.min(page.len())).unwrap_or(&[]));
            if let Some(rest) = page.get(24..) {
                out.extend(rest.iter().zip(self.full.iter()).map(|(a, b)| a ^ b));
                if rest.len() > self.full.len() {
                    out.extend(self.ks.crypt(&rest[self.full.len()..]));
                }
            }
            out
        } else {
            page.iter()
                .zip(self.full.iter().chain(std::iter::repeat(&0u8)))
                .map(|(a, b)| a ^ b)
                .collect()
        }
    }
}

/// Page size from header bytes 16..18 (BE; 1 = 65536), validated as a power of two in 512..=65536.
pub fn page_size_of(db: &[u8]) -> Result<u32, PagerError> {
    let raw = db.get(16..18).ok_or(PagerError::Empty)?;
    let v = u16::from_be_bytes([raw[0], raw[1]]) as u32;
    let ps = if v == 1 { 65536 } else { v };
    if !(512..=65536).contains(&ps) || !ps.is_power_of_two() {
        return Err(PagerError::BadPageSize(ps));
    }
    Ok(ps)
}

pub fn build(db: &[u8], wal: Option<&[u8]>, key: &Key) -> Result<Images, PagerError> {
    if db.len() < 100 {
        return Err(PagerError::Empty);
    }
    let mut notes = Vec::new();
    let encrypted = !db.starts_with(SQLITE_MAGIC);
    if encrypted && !key_matches(key, db) {
        return Err(PagerError::NotEncryptedOrWrongKey);
    }
    if !encrypted {
        notes.push("input is a plain (unencrypted) SQLite file".to_string());
    }
    let ps = page_size_of(db)?;
    let psz = ps as usize;
    let pages = db.len() / psz;
    if pages == 0 {
        return Err(PagerError::Empty);
    }
    if db.len() % psz != 0 {
        notes.push(format!(
            "trailing partial page of {} bytes ignored",
            db.len() % psz
        ));
    }
    let codec = PageCodec::new(key, psz, encrypted);
    let mut db_only = Vec::with_capacity(pages * psz);
    for p in 0..pages {
        db_only.extend(codec.decrypt(&db[p * psz..(p + 1) * psz], p == 0));
    }
    let header_18_19 = [db_only[18], db_only[19]];
    let (merged, report) = wal::replay(&db_only, wal, ps, &codec, &mut notes);
    Ok(Images {
        db_only,
        merged,
        page_size: ps,
        header_18_19,
        encrypted,
        wal: report,
        notes,
    })
}
