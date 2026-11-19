//! Snapshot diff keyed by natural keys, compared as multisets (spec §10).
use crate::bookmarks::event_key;
use crate::case::Case;
use crate::model::{DbStatus, Prov, SqlVal};
use crate::views::key_label;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Added,
    Removed,
    Changed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffRow {
    pub view: String,
    pub key: String,
    pub change: Change,
    pub a: Option<String>,
    pub b: Option<String>,
}

type Bag = BTreeMap<(String, String), Vec<String>>;

/// (view, natural key) → content signatures (multiset). Provenance status is not part of the value:
/// a row moving from WAL to the main file between snapshots is not a change.
fn bag(c: &Case) -> Bag {
    let mut m: Bag = BTreeMap::new();
    let removed = |p: &Prov| {
        matches!(
            p,
            Prov::Db {
                status: DbStatus::RemovedByWal,
                ..
            }
        )
    };
    for e in c.events.iter().filter(|e| !removed(&e.prov)) {
        // display and raw of every field, JSON-encoded so no two different field sets serialise alike
        let fields: Vec<(&str, &str, &str)> = e
            .fields
            .iter()
            .map(|f| (f.name.as_str(), f.display.as_str(), f.raw.as_str()))
            .collect();
        let value = serde_json::to_string(&(&e.summary, fields)).unwrap_or_default();
        m.entry((format!("{:?}", e.kind), event_key(c, e)))
            .or_default()
            .push(value);
    }
    for t in &c.raw {
        for (vals, p) in t.rows.iter().filter(|(_, p)| !removed(p)) {
            let key = match p {
                Prov::Db { key, .. } => format!(
                    "{} [{}]",
                    key_label(key),
                    crate::decode::values::hex(&crate::provenance::key_bytes(key))
                ),
                _ => String::new(),
            };
            let typed: Vec<String> = vals.iter().map(typed_value).collect();
            let value = serde_json::to_string(&(&t.columns, typed)).unwrap_or_default();
            m.entry((format!("raw {}", t.name), key))
                .or_default()
                .push(value);
        }
    }
    m
}

/// Type-tagged cell value: NULL, integer, real, text and blob never compare equal to each other.
fn typed_value(v: &SqlVal) -> String {
    match v {
        SqlVal::Null => "null".into(),
        SqlVal::Int(i) => format!("int:{i}"),
        SqlVal::Real(f) => format!("real:{:016x}", f.to_bits()),
        SqlVal::Text(s) => format!("text:{s}"),
        SqlVal::Blob(b) => format!("blob:{}", crate::decode::values::hex(b)),
    }
}

pub fn diff(a: &Case, b: &Case) -> Result<Vec<DiffRow>, String> {
    if a.opts != b.opts {
        return Err("the two cases were loaded with different time-zone or volume-mapping settings; reload them with the same settings".into());
    }
    let (ba, bb) = (bag(a), bag(b));
    let mut keys: Vec<&(String, String)> = ba.keys().chain(bb.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut out = Vec::new();
    for k in keys {
        let mut va = ba.get(k).cloned().unwrap_or_default();
        let mut vb = bb.get(k).cloned().unwrap_or_default();
        va.sort();
        vb.sort();
        // multiset difference: drop values present on both sides (counted)
        let (mut ra, mut rb) = (Vec::new(), Vec::new());
        let (mut i, mut j) = (0, 0);
        while i < va.len() || j < vb.len() {
            match (va.get(i), vb.get(j)) {
                (Some(x), Some(y)) if x == y => {
                    i += 1;
                    j += 1;
                }
                (Some(x), Some(y)) if x < y => {
                    ra.push(x.clone());
                    i += 1;
                }
                (Some(_), Some(y)) => {
                    rb.push(y.clone());
                    j += 1;
                }
                (Some(x), None) => {
                    ra.push(x.clone());
                    i += 1;
                }
                (None, Some(y)) => {
                    rb.push(y.clone());
                    j += 1;
                }
                (None, None) => break,
            }
        }
        let n = ra.len().min(rb.len());
        let row = |change, a: Option<String>, b: Option<String>| DiffRow {
            view: k.0.clone(),
            key: k.1.clone(),
            change,
            a,
            b,
        };
        for x in 0..n {
            out.push(row(
                Change::Changed,
                Some(ra[x].clone()),
                Some(rb[x].clone()),
            ));
        }
        out.extend(
            ra[n..]
                .iter()
                .map(|x| row(Change::Removed, Some(x.clone()), None)),
        );
        out.extend(
            rb[n..]
                .iter()
                .map(|y| row(Change::Added, None, Some(y.clone()))),
        );
    }
    Ok(out)
}

/// Diff rows as CSV (UTF-8 with BOM).
pub fn write_diff_csv(rows: &[DiffRow], w: &mut dyn std::io::Write) -> std::io::Result<()> {
    let v = crate::views::View {
        name: "diff".into(),
        columns: ["View", "Key", "Change", "A", "B"]
            .map(String::from)
            .to_vec(),
        rows: rows
            .iter()
            .map(|r| crate::views::ViewRow {
                cells: vec![
                    r.view.clone(),
                    r.key.clone(),
                    format!("{:?}", r.change),
                    r.a.clone().unwrap_or_default(),
                    r.b.clone().unwrap_or_default(),
                ],
                raw: vec![],
                prov: None,
                node: None,
            })
            .collect(),
    };
    crate::export::table::write_csv(&v, w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::{OpenRequest, open};
    use crate::model::EventKind;
    use crate::views::tests::case;

    fn fx(v: &str) -> std::sync::Arc<crate::case::Case> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(v);
        open(
            &OpenRequest {
                path: p,
                key_dll: None,
                mft: None,
                opts: Default::default(),
            },
            &|_| {},
        )
        .unwrap()
    }

    #[test]
    fn identical_cases_have_no_diff() {
        assert!(diff(&case(), &case()).unwrap().is_empty());
    }

    #[test]
    fn diff_detects_committed_wal_transaction() {
        let rows = diff(&fx("uncommitted_tail"), &fx("multi_commit")).unwrap();
        assert!(
            rows.iter()
                .any(|r| r.change == Change::Added && r.view == "FileHashed"),
            "{rows:?}"
        );
        assert!(
            rows.iter()
                .any(|r| r.change == Change::Added && r.view == "raw FileHashes")
        );
        assert!(rows.iter().all(|r| r.change == Change::Added), "{rows:?}");
    }

    #[test]
    fn diff_multiset_duplicates() {
        let a = case();
        let mut b = (*a).clone();
        let dup = b
            .events
            .iter()
            .find(|e| e.kind == EventKind::LowFiHit)
            .unwrap()
            .clone();
        let mut d2 = dup.clone();
        d2.id = b.events.len() as u32;
        b.events.push(d2);
        let rows = diff(&a, &b).unwrap();
        assert_eq!(rows.iter().filter(|r| r.change == Change::Added).count(), 1);
        let back = diff(&b, &a).unwrap();
        assert_eq!(
            back.iter().filter(|r| r.change == Change::Removed).count(),
            1
        );
    }

    #[test]
    fn diff_reports_changed_values_under_the_same_key() {
        let a = case();
        let mut b = (*a).clone();
        let e = b
            .events
            .iter_mut()
            .find(|e| e.kind == EventKind::RegistryChange)
            .unwrap();
        e.fields
            .iter_mut()
            .find(|f| f.name == "NewRegData")
            .unwrap()
            .display = "3".into();
        let rows = diff(&a, &b).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].change, Change::Changed);
    }

    #[test]
    fn wal_deletion_is_reported_as_removed() {
        // ck_fail_mid applies txns 1–2 (APC row 1 present); salt_reset_stale applies txns 1–3 (row 1 deleted by the WAL).
        let rows = diff(&fx("ck_fail_mid"), &fx("salt_reset_stale")).unwrap();
        assert!(
            rows.iter()
                .any(|r| r.change == Change::Removed && r.view == "NoCertExec"),
            "{rows:?}"
        );
        assert!(
            rows.iter()
                .any(|r| r.change == Change::Removed && r.view == "raw AttributePersistContext")
        );
    }

    #[test]
    fn typed_values_null_vs_empty_text_differ() {
        use crate::model::{DbStatus, RawTable, RowKey, SqlVal};
        let mk = |v: SqlVal| {
            let mut c = (*case()).clone();
            c.raw.push(RawTable {
                name: "T".into(),
                columns: vec!["value".into()],
                rows: vec![(
                    vec![v],
                    Prov::Db {
                        table: "T".into(),
                        key: RowKey::Rowid(1),
                        status: DbStatus::InBoth,
                        old: None,
                    },
                )],
                readable: true,
            });
            c
        };
        let rows = diff(&mk(SqlVal::Null), &mk(SqlVal::Text(String::new()))).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            diff(&mk(SqlVal::Int(1)), &mk(SqlVal::Text("1".into())))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn diff_refuses_mismatched_opts() {
        let a = case();
        let mut b = (*a).clone();
        b.opts.tz = crate::decode::time::Tz { offset_min: 60 };
        assert!(diff(&a, &b).is_err());
    }
}
