//! WAL validation and replay with SQLite semantics on the stored (encrypted) checksum chain (spec §3).
use super::PageCodec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WalStop {
    SaltMismatch { frame: u32, offset: u64 },
    ChecksumMismatch { frame: u32, offset: u64 },
    Truncated { offset: u64 },
    BadPageNo { frame: u32, page: u32 },
}

#[derive(Clone, Debug, Default)]
pub struct WalReport {
    pub present: bool,
    pub header_valid: bool,
    pub big_endian: bool,
    pub page_size: u32,
    pub salts: (u32, u32),
    /// Complete frames physically present.
    pub frames_total: u32,
    /// Frames whose salt and cumulative checksum validated.
    pub frames_valid: u32,
    /// Frames up to and including the last valid commit frame.
    pub frames_applied: u32,
    pub commits: u32,
    pub stop: Option<WalStop>,
    /// Valid frames after the last commit (never applied).
    pub ignored_tail_frames: u32,
}

/// SQLite WAL checksum over 8-byte chunks of u32 words.
pub fn checksum(data: &[u8], mut s0: u32, mut s1: u32, big: bool) -> (u32, u32) {
    let word = |c: &[u8]| {
        let a = [c[0], c[1], c[2], c[3]];
        if big {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    };
    for c in data.as_chunks::<8>().0 {
        s0 = s0.wrapping_add(word(&c[0..4])).wrapping_add(s1);
        s1 = s1.wrapping_add(word(&c[4..8])).wrapping_add(s0);
    }
    (s0, s1)
}

/// Largest image the replay will build (matches the 2 GiB input cap, §4).
const MAX_IMAGE: u64 = 2 * 1024 * 1024 * 1024;

fn be32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Returns the merged image (db_only when nothing applies) and the report.
pub(super) fn replay(
    db_only: &[u8],
    wal: Option<&[u8]>,
    ps: u32,
    codec: &PageCodec,
    notes: &mut Vec<String>,
) -> (Vec<u8>, WalReport) {
    let mut r = WalReport::default();
    let Some(w) = wal else {
        return (db_only.to_vec(), r);
    };
    r.present = true;
    if w.len() < 32 {
        notes.push(format!(
            "WAL has {} bytes (< 32-byte header); not applied",
            w.len()
        ));
        return (db_only.to_vec(), r);
    }
    let magic = be32(w, 0);
    r.big_endian = magic & 1 == 1;
    r.page_size = be32(w, 8);
    r.salts = (be32(w, 16), be32(w, 20));
    let hck = checksum(&w[..24], 0, 0, r.big_endian);
    let version = be32(w, 4);
    r.header_valid =
        (magic & !1) == 0x377f_0682 && version == 3_007_000 && hck == (be32(w, 24), be32(w, 28));
    if !r.header_valid {
        notes.push(format!(
            "WAL header invalid (magic {magic:#x}, version {version}, or checksum); not applied"
        ));
        return (db_only.to_vec(), r);
    }
    if r.page_size != ps {
        notes.push(format!(
            "WAL page size {} differs from DB page size {ps}; not applied",
            r.page_size
        ));
        r.header_valid = false;
        return (db_only.to_vec(), r);
    }
    let psz = ps as usize;
    let fsz = 24 + psz;
    r.frames_total = ((w.len() - 32) / fsz) as u32;

    let mut chain = hck;
    let mut last_commit: Option<(usize, u32)> = None; // (frame index, db size in pages)
    let mut txn_start = 0usize;
    let orig_pages = (db_only.len() / psz) as u64;
    let mut max_pg_seen = 0u64;
    let mut off = 32usize;
    let mut idx = 0usize;
    while off + fsz <= w.len() {
        let pg = be32(w, off);
        let commit = be32(w, off + 4);
        if (be32(w, off + 8), be32(w, off + 12)) != r.salts {
            r.stop = Some(WalStop::SaltMismatch {
                frame: idx as u32,
                offset: off as u64,
            });
            break;
        }
        let c = checksum(&w[off..off + 8], chain.0, chain.1, r.big_endian);
        let c = checksum(&w[off + 24..off + fsz], c.0, c.1, r.big_endian);
        if c != (be32(w, off + 16), be32(w, off + 20)) {
            r.stop = Some(WalStop::ChecksumMismatch {
                frame: idx as u32,
                offset: off as u64,
            });
            break;
        }
        if pg == 0 {
            r.stop = Some(WalStop::BadPageNo {
                frame: idx as u32,
                page: 0,
            });
            break;
        }
        chain = c;
        max_pg_seen = max_pg_seen.max(pg as u64);
        if commit != 0 {
            // A commit cannot make the DB larger than every page it could contain, nor exceed the 2 GiB image cap.
            let limit = orig_pages.max(max_pg_seen);
            if commit as u64 > limit || (commit as u64).saturating_mul(psz as u64) > MAX_IMAGE {
                r.stop = Some(WalStop::BadPageNo {
                    frame: idx as u32,
                    page: commit,
                });
                break;
            }
            let bad = (txn_start..=idx).find(|&i| be32(w, 32 + i * fsz) > commit);
            if let Some(i) = bad {
                r.stop = Some(WalStop::BadPageNo {
                    frame: i as u32,
                    page: be32(w, 32 + i * fsz),
                });
                break;
            }
            last_commit = Some((idx, commit));
            r.commits += 1;
            txn_start = idx + 1;
        }
        r.frames_valid += 1;
        idx += 1;
        off += fsz;
    }
    if r.stop.is_none() && off < w.len() {
        r.stop = Some(WalStop::Truncated { offset: off as u64 });
    }
    let Some((last, db_pages)) = last_commit else {
        r.ignored_tail_frames = r.frames_valid;
        return (db_only.to_vec(), r);
    };
    r.frames_applied = (last + 1) as u32;
    r.ignored_tail_frames = r.frames_valid - r.frames_applied;

    let mut merged = db_only.to_vec();
    merged.resize(db_pages as usize * psz, 0);
    for i in 0..=last {
        let o = 32 + i * fsz;
        let pg = be32(w, o) as usize;
        if pg > db_pages as usize {
            continue; // page beyond the final committed size (truncated by a later transaction)
        }
        let plain = codec.decrypt(&w[o + 24..o + fsz], pg == 1);
        let dst = (pg - 1) * psz;
        merged[dst..dst + psz].copy_from_slice(&plain);
    }
    (merged, r)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::embedded_key;

    const PS: usize = 512;

    /// Plain (unencrypted) WAL with valid header and frame checksums.
    fn wal(version: u32, frames: &[(u32, u32)]) -> Vec<u8> {
        let mut h = Vec::new();
        for v in [0x377f_0682u32, version, PS as u32, 0, 11, 22] {
            h.extend(v.to_be_bytes());
        }
        let mut c = checksum(&h, 0, 0, false);
        h.extend(c.0.to_be_bytes());
        h.extend(c.1.to_be_bytes());
        for &(pg, commit) in frames {
            let mut fh = Vec::new();
            fh.extend(pg.to_be_bytes());
            fh.extend(commit.to_be_bytes());
            let payload = vec![pg as u8; PS];
            c = checksum(&fh, c.0, c.1, false);
            c = checksum(&payload, c.0, c.1, false);
            for v in [11u32, 22, c.0, c.1] {
                fh.extend(v.to_be_bytes());
            }
            h.extend(fh);
            h.extend(payload);
        }
        h
    }

    fn run(db_pages: usize, w: &[u8]) -> (Vec<u8>, WalReport) {
        let codec = PageCodec::new(&embedded_key(), PS, false);
        let db = vec![0u8; db_pages * PS];
        replay(&db, Some(w), PS as u32, &codec, &mut Vec::new())
    }

    #[test]
    fn shrink_after_earlier_write_does_not_panic() {
        let (m, r) = run(2, &wal(3007000, &[(3, 3), (1, 2)]));
        assert_eq!(r.commits, 2);
        assert_eq!(m.len(), 2 * PS);
        assert_eq!(m[0], 1);
    }

    #[test]
    fn huge_commit_size_is_rejected_without_allocation() {
        let (m, r) = run(1, &wal(3007000, &[(1, 0xFFFF_FFFF)]));
        assert_eq!(r.frames_applied, 0);
        assert!(matches!(r.stop, Some(WalStop::BadPageNo { .. })));
        assert_eq!(m.len(), PS);
    }

    #[test]
    fn unsupported_version_not_applied() {
        let (m, r) = run(1, &wal(3007001, &[(1, 1)]));
        assert!(!r.header_valid);
        assert_eq!(r.frames_applied, 0);
        assert_eq!(m, vec![0u8; PS]);
    }

    #[test]
    fn growth_within_written_pages_applies() {
        let (m, r) = run(1, &wal(3007000, &[(2, 0), (3, 3)]));
        assert_eq!(r.frames_applied, 2);
        assert_eq!(m.len(), 3 * PS);
        assert_eq!(m[2 * PS], 3);
    }
}
