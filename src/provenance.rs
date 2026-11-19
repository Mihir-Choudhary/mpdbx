//! Endpoint comparison of the DB-only and merged images (spec §5.5).
//! Describes the two endpoints only; DB-only is not claimed to be a pristine pre-WAL state.
use crate::model::{DbStatus, RowKey, SqlVal};
use crate::sqldb::{Db, Rows, TableInfo};
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct ProvRow {
    pub key: RowKey,
    pub values: Vec<SqlVal>,
    pub status: DbStatus,
    /// DB-only values for WalModified / RemovedByWal.
    pub old: Option<Vec<SqlVal>>,
}

#[derive(Clone, Debug)]
pub struct TableProv {
    pub info: Option<TableInfo>,
    /// True when the table could be read from the merged image (or, failing that, from DB-only).
    pub readable: bool,
    pub error: Option<String>,
    pub db_only_count: Option<usize>,
    pub merged_count: Option<usize>,
    pub rows: Vec<ProvRow>,
}

#[derive(Clone, Debug, Default)]
pub struct ProvMap {
    pub tables: HashMap<String, TableProv>,
}

fn enc_val(v: &SqlVal, out: &mut Vec<u8>) {
    match v {
        SqlVal::Null => out.push(0),
        SqlVal::Int(i) => {
            out.push(1);
            out.extend(i.to_le_bytes());
        }
        SqlVal::Real(f) => {
            out.push(2);
            out.extend(f.to_bits().to_le_bytes());
        }
        SqlVal::Text(s) => {
            out.push(3);
            out.extend((s.len() as u64).to_le_bytes());
            out.extend(s.as_bytes());
        }
        SqlVal::Blob(b) => {
            out.push(4);
            out.extend((b.len() as u64).to_le_bytes());
            out.extend(b);
        }
    }
}

fn enc_vals(vs: &[SqlVal]) -> Vec<u8> {
    let mut out = Vec::new();
    for v in vs {
        enc_val(v, &mut out);
    }
    out
}

/// Canonical bytes of a row key (floats bitwise).
pub fn key_bytes(k: &RowKey) -> Vec<u8> {
    let (tag, vals): (u8, &[SqlVal]) = match k {
        RowKey::Rowid(i) => return [&[0u8][..], &i.to_le_bytes()].concat(),
        RowKey::Pk(v) => (1, v),
        RowKey::Full(v) => (2, v),
    };
    let mut out = vec![tag];
    out.extend(enc_vals(vals));
    out
}

/// `db_only`: `None` = table absent from the DB-only schema (created in the WAL); `Some(Err)` = unreadable.
pub fn classify_table(
    db_only: Option<Result<Rows, String>>,
    merged: Result<Rows, String>,
) -> TableProv {
    let mk = |key, values, status, old| ProvRow {
        key,
        values,
        status,
        old,
    };
    match (db_only, merged) {
        (base, Err(e)) => {
            let (rows, count) = match base {
                Some(Ok(a)) => {
                    let n = a.len();
                    (
                        a.into_iter()
                            .map(|(k, v)| mk(k, v, DbStatus::Unknown, None))
                            .collect(),
                        Some(n),
                    )
                }
                _ => (Vec::new(), None),
            };
            let readable = count.is_some();
            TableProv {
                info: None,
                readable,
                error: Some(e),
                db_only_count: count,
                merged_count: None,
                rows,
            }
        }
        (Some(Err(e)), Ok(b)) => {
            let n = b.len();
            let rows = b
                .into_iter()
                .map(|(k, v)| mk(k, v, DbStatus::Unknown, None))
                .collect();
            TableProv {
                info: None,
                readable: true,
                error: Some(e),
                db_only_count: None,
                merged_count: Some(n),
                rows,
            }
        }
        (None, Ok(b)) => {
            let n = b.len();
            let rows = b
                .into_iter()
                .map(|(k, v)| mk(k, v, DbStatus::WalOnly, None))
                .collect();
            TableProv {
                info: None,
                readable: true,
                error: None,
                db_only_count: Some(0),
                merged_count: Some(n),
                rows,
            }
        }
        (Some(Ok(a)), Ok(b)) => {
            let (na, nb) = (a.len(), b.len());
            let mut base: HashMap<Vec<u8>, (RowKey, Vec<SqlVal>)> = a
                .into_iter()
                .map(|(k, v)| (key_bytes(&k), (k, v)))
                .collect();
            let mut rows = Vec::with_capacity(nb);
            for (k, v) in b {
                match base.remove(&key_bytes(&k)) {
                    Some((_, old)) if enc_vals(&old) == enc_vals(&v) => {
                        rows.push(mk(k, v, DbStatus::InBoth, None))
                    }
                    Some((_, old)) => rows.push(mk(k, v, DbStatus::WalModified, Some(old))),
                    None => rows.push(mk(k, v, DbStatus::WalOnly, None)),
                }
            }
            let mut removed: Vec<_> = base.into_values().collect();
            removed.sort_by_key(|(k, _)| key_bytes(k));
            for (k, v) in removed {
                rows.push(mk(k, v.clone(), DbStatus::RemovedByWal, Some(v)));
            }
            TableProv {
                info: None,
                readable: true,
                error: None,
                db_only_count: Some(na),
                merged_count: Some(nb),
                rows,
            }
        }
    }
}

/// Classify every table of the merged image (and tables that exist only in DB-only).
pub fn classify(db_only: &Db, merged: &Db) -> ProvMap {
    let a_tables: HashMap<String, TableInfo> = db_only
        .tables()
        .into_iter()
        .map(|t| (t.name.clone(), t))
        .collect();
    let b_tables = merged.tables();
    let mut map = ProvMap::default();
    for t in &b_tables {
        let base = a_tables.get(&t.name).map(|ta| db_only.rows(ta));
        let mut tp = classify_table(base, merged.rows(t));
        tp.info = Some(t.clone());
        map.tables.insert(t.name.clone(), tp);
    }
    for (name, ta) in &a_tables {
        if !map.tables.contains_key(name) {
            // dropped by the WAL: every DB-only row is RemovedByWal
            let mut tp = classify_table(Some(db_only.rows(ta)), Ok(Vec::new()));
            tp.info = Some(ta.clone());
            map.tables.insert(name.clone(), tp);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{DbStatus, RowKey, SqlVal};
    use crate::sqldb;

    fn images() -> crate::pager::Images {
        let d =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_commit");
        let db = std::fs::read(d.join("mpenginedb.db")).unwrap();
        let wal = std::fs::read(d.join("mpenginedb.db-wal")).unwrap();
        crate::pager::build(&db, Some(&wal), &crate::crypto::embedded_key()).unwrap()
    }

    fn prov() -> ProvMap {
        let img = images();
        classify(
            &sqldb::open(&img.db_only).unwrap(),
            &sqldb::open(&img.merged).unwrap(),
        )
    }

    fn row<'a>(p: &'a ProvMap, t: &str, k: &RowKey) -> &'a ProvRow {
        p.tables[t].rows.iter().find(|r| &r.key == k).unwrap()
    }

    #[test]
    fn insert_is_walonly() {
        assert_eq!(
            row(&prov(), "BackupProcessInfo", &RowKey::Rowid(3)).status,
            DbStatus::WalOnly
        );
    }

    #[test]
    fn unchanged_is_inboth() {
        assert_eq!(
            row(&prov(), "BackupProcessInfo", &RowKey::Rowid(2)).status,
            DbStatus::InBoth
        );
    }

    #[test]
    fn update_is_walmodified_with_old() {
        let p = prov();
        let r = row(&p, "BackupProcessInfo", &RowKey::Rowid(1));
        assert_eq!(r.status, DbStatus::WalModified);
        let old = r.old.as_ref().unwrap();
        assert_eq!(old[3], SqlVal::Int(134369015368153546));
        assert_eq!(r.values[3], SqlVal::Int(134369015368153547));
    }

    #[test]
    fn delete_is_removed_by_wal() {
        let p = prov();
        let r = row(&p, "AttributePersistContext", &RowKey::Rowid(1));
        assert_eq!(r.status, DbStatus::RemovedByWal);
        assert!(r.old.is_some());
    }

    #[test]
    fn without_rowid_keyed_by_pk() {
        let p = prov();
        let r = row(
            &p,
            "InventoryState",
            &RowKey::Pk(vec![SqlVal::Text("schema_version".into())]),
        );
        assert_eq!(r.status, DbStatus::WalOnly);
    }

    #[test]
    fn unreadable_baseline_is_unknown() {
        let merged = vec![(RowKey::Rowid(1), vec![SqlVal::Int(1)])];
        let t = classify_table(Some(Err("corrupt".into())), Ok(merged));
        assert!(t.readable);
        assert_eq!(t.rows[0].status, DbStatus::Unknown);
    }

    #[test]
    fn table_absent_from_baseline_is_walonly() {
        let merged = vec![(RowKey::Rowid(1), vec![SqlVal::Int(1)])];
        let t = classify_table(None, Ok(merged));
        assert_eq!(t.rows[0].status, DbStatus::WalOnly);
    }

    fn image(sql: &str) -> Vec<u8> {
        let mut c = rusqlite::Connection::open_in_memory().unwrap();
        c.execute_batch(sql).unwrap();
        c.serialize(rusqlite::MAIN_DB).unwrap().to_vec()
    }

    fn classify_sql(a: &str, b: &str) -> ProvMap {
        classify(
            &sqldb::open(&image(a)).unwrap(),
            &sqldb::open(&image(b)).unwrap(),
        )
    }

    #[test]
    fn declared_rowid_column_does_not_shadow_identity() {
        let s = "CREATE TABLE t(rowid INTEGER, v TEXT); INSERT INTO t VALUES(7,'a'),(7,'b');";
        let p = classify_sql(s, s);
        assert!(
            p.tables["t"]
                .rows
                .iter()
                .all(|r| r.status == DbStatus::InBoth),
            "{:?}",
            p.tables["t"].rows
        );
        assert_eq!(p.tables["t"].rows.len(), 2);
    }

    #[test]
    fn generated_columns_are_kept_aligned() {
        let base = "CREATE TABLE g(a INT, b INT GENERATED ALWAYS AS (a+1), c TEXT); INSERT INTO g(a,c) VALUES(1,'before');";
        let p = classify_sql(base, &base.replace("'before'", "'after'"));
        let r = &p.tables["g"].rows[0];
        assert_eq!(r.status, DbStatus::WalModified);
        assert_eq!(
            p.tables["g"].info.as_ref().unwrap().columns,
            vec!["a", "b", "c"]
        );
        assert_eq!(r.values[2], SqlVal::Text("after".into()));
    }

    #[test]
    fn invalid_utf8_text_stays_distinct() {
        let a = "CREATE TABLE u(v TEXT); INSERT INTO u VALUES(CAST(x'80' AS TEXT));";
        let p = classify_sql(a, &a.replace("x'80'", "x'81'"));
        let r = &p.tables["u"].rows[0];
        assert_eq!(r.status, DbStatus::WalModified);
        assert_eq!(r.values[0], SqlVal::Text("\\x81".into()));
    }

    #[test]
    fn unreadable_table_metadata_is_unknown_not_absent() {
        let s = "CREATE TABLE ok(a); PRAGMA writable_schema=ON; \
                 INSERT INTO sqlite_master VALUES('table','vt','vt',0,'CREATE VIRTUAL TABLE vt USING nosuchmodule()');";
        let p = classify_sql(s, s);
        let t = &p.tables["vt"];
        assert!(t.error.is_some());
        assert!(!t.readable);
    }

    #[test]
    fn open_rejects_garbage() {
        assert!(sqldb::open(&[0u8; 100]).is_err());
    }

    #[test]
    fn query_only_blocks_writes() {
        let db = sqldb::open(&images().merged).unwrap();
        assert!(db.conn().execute("CREATE TABLE x(a)", []).is_err());
    }
}
