//! Results scan records (spec §3; only GUID/start/end are validated).
use super::container::{MAX_RECORD, ParseErr, open_container};
use super::store::files_in;
use crate::crypto::{Key, Rc4Ks};
use crate::decode::values::fmt_guid;
use crate::evidence::{Input, read_input};
use crate::model::Ft;
use std::path::Path;

#[derive(Clone, Debug)]
pub struct ScanRec {
    pub file: String,
    /// Subdirectory name ("Quick", "Resource", …).
    pub category: String,
    pub guid: Option<String>,
    pub start: Option<Ft>,
    pub end: Option<Ft>,
    pub unverified_sec1: Vec<u8>,
    pub unverified_sec2_tail: Vec<u8>,
    /// Bytes after the container's declared sections.
    pub trailing: u32,
}

fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8)
        .map(|x| u64::from_le_bytes([x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]]))
}

/// `results_dir` = `…\History\Results`; every subdirectory is a category.
pub fn load_results(results_dir: &Path, key: &Key) -> (Vec<ScanRec>, Vec<ParseErr>, Vec<Input>) {
    let ks = Rc4Ks::new(key);
    let (mut recs, mut errs, mut inputs) = (Vec::new(), Vec::new(), Vec::new());
    let mut cats = Vec::new();
    match std::fs::read_dir(results_dir) {
        Ok(rd) => {
            for ent in rd {
                match ent.and_then(|e| e.file_type().map(|t| (e, t))) {
                    Ok((e, t)) if t.is_dir() => {
                        cats.push(e.file_name().to_string_lossy().into_owned())
                    }
                    Ok(_) => {}
                    Err(x) => errs.push(ParseErr {
                        file: "Results".into(),
                        offset: 0,
                        reason: x.to_string(),
                    }),
                }
            }
        }
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => {}
        Err(x) => errs.push(ParseErr {
            file: "Results".into(),
            offset: 0,
            reason: format!("cannot list: {x}"),
        }),
    }
    cats.sort();
    for cat in cats {
        let (files, e) = files_in(&results_dir.join(&cat), &format!("Results/{cat}"));
        errs.extend(e);
        for (name, path) in files {
            let label = format!("{cat}/{name}");
            let input = match read_input(&path, MAX_RECORD) {
                Ok(i) => i,
                Err(e) => {
                    errs.push(ParseErr {
                        file: label,
                        offset: 0,
                        reason: e,
                    });
                    continue;
                }
            };
            match open_container(&input.bytes, &ks) {
                Ok(c) if c.sec1.len() < 16 || c.sec2.len() < 16 => errs.push(ParseErr {
                    file: label,
                    offset: 0x28,
                    reason: format!(
                        "sections too short for GUID/start/end ({} / {} bytes)",
                        c.sec1.len(),
                        c.sec2.len()
                    ),
                }),
                Ok(c) => recs.push(ScanRec {
                    file: label,
                    category: cat.clone(),
                    guid: c.sec1.get(..16).and_then(fmt_guid),
                    start: u64_at(&c.sec2, 0),
                    end: u64_at(&c.sec2, 8),
                    unverified_sec1: c.sec1.get(16..).unwrap_or_default().to_vec(),
                    unverified_sec2_tail: c.sec2.get(16..).unwrap_or_default().to_vec(),
                    trailing: c.trailing,
                }),
                Err(mut e) => {
                    e.file = label;
                    errs.push(e);
                }
            }
            inputs.push(input);
        }
    }
    (recs, errs, inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::embedded_key;
    /// A reference copy under `MPDBX_COPIES` (local evidence, never committed); `None` when the variable is unset.
    fn copy_dir(rel: &str) -> Option<std::path::PathBuf> {
        std::env::var_os("MPDBX_COPIES").map(|r| std::path::PathBuf::from(r).join(rel))
    }

    #[test]
    fn results_guid_start_end() {
        let d =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/history/Results");
        let (recs, errs, _) = load_results(&d, &embedded_key());
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.category, "Quick");
        assert_eq!(
            r.guid.as_deref(),
            Some("{52C578BA-7190-4A14-84B3-57F157281CB5}")
        );
        assert_eq!(r.start, Some(134369015368153546));
        assert_eq!(r.end, Some(134369015368153546 + 410_000_000));
    }

    #[test]
    fn short_sections_are_diagnosed() {
        let d = crate::evidence::tests::tmpdir("res_short").join("Results");
        std::fs::create_dir_all(d.join("Quick")).unwrap();
        std::fs::write(
            d.join("Quick").join("{X}"),
            crate::history::container::tests::make(&[0u8; 15], &[0u8; 15]),
        )
        .unwrap();
        let (recs, errs, _) = load_results(&d, &embedded_key());
        assert!(recs.is_empty());
        assert_eq!(errs.len(), 1);
    }

    /// Local evidence only: every real Results record opens and its GUID equals its file name.
    #[test]
    #[ignore]
    fn real_results_vss9_guid_matches_name() {
        let Some(d) = copy_dir("vss9/Defender_History/Results") else {
            eprintln!("skipped: set MPDBX_COPIES to the reference copies folder");
            return;
        };
        let d = d.as_path();
        let (recs, errs, _) = load_results(d, &embedded_key());
        assert!(errs.is_empty(), "{errs:?}");
        assert!(recs.len() > 100);
        for r in &recs {
            let name = r.file.rsplit('/').next().unwrap();
            assert_eq!(r.guid.as_deref(), Some(name), "{}", r.file);
            assert!(matches!(
                crate::decode::time::classify_ft(r.start.unwrap() as i64),
                crate::decode::time::FtClass::Plausible(_)
            ));
        }
    }
}
