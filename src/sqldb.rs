//! In-memory SQLite images (spec §3 Loading images, §4).
use crate::model::{RowKey, SqlVal};
use rusqlite::types::ValueRef;

pub struct Db {
    conn: rusqlite::Connection,
}

#[derive(Clone, Debug)]
pub struct TableInfo {
    pub name: String,
    pub columns: Vec<String>,
    pub without_rowid: bool,
    pub pk_cols: Vec<usize>,
    /// Name used to select the intrinsic rowid (`rowid`, `_rowid_` or `oid`, whichever no column shadows).
    pub rowid_alias: Option<String>,
    /// Metadata could not be read (e.g. virtual table with an unavailable module); `rows()` then fails.
    pub error: Option<String>,
}

pub type Rows = Vec<(RowKey, Vec<SqlVal>)>;

fn quote(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// UTF-8 text unchanged; each invalid byte becomes `\xNN`, so distinct byte strings stay distinct.
pub fn text_lossless(b: &[u8]) -> String {
    let mut out = String::with_capacity(b.len());
    let mut rest = b;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(s) => {
                out.push_str(s);
                break;
            }
            Err(e) => {
                let (ok, bad) = rest.split_at(e.valid_up_to());
                out.push_str(std::str::from_utf8(ok).unwrap_or_default());
                let n = e.error_len().unwrap_or(bad.len()).max(1);
                for x in &bad[..n] {
                    out.push_str(&format!("\\x{x:02x}"));
                }
                rest = &bad[n..];
            }
        }
    }
    out
}

fn val(v: ValueRef<'_>) -> SqlVal {
    match v {
        ValueRef::Null => SqlVal::Null,
        ValueRef::Integer(i) => SqlVal::Int(i),
        ValueRef::Real(f) => SqlVal::Real(f),
        ValueRef::Text(t) => SqlVal::Text(text_lossless(t)),
        ValueRef::Blob(b) => SqlVal::Blob(b.to_vec()),
    }
}

/// Load a decrypted image read-only. The loading copy gets header bytes 18–19 set to 1 (rollback mode),
/// because SQLite cannot deserialize a WAL-mode image; the caller's bytes are not modified.
pub fn open(image: &[u8]) -> Result<Db, String> {
    if image.len() < 100 {
        return Err("image shorter than the SQLite header".into());
    }
    let mut img = image.to_vec();
    img[18] = 1;
    img[19] = 1;
    // in-header page count: zero it so SQLite always sizes the database from the buffer (a stale count from a copy
    // taken mid-checkpoint, or one not rewritten by a WAL commit, would truncate or reject the image)
    img[28..32].fill(0);
    let mut conn = rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?;
    conn.deserialize_read_exact(rusqlite::MAIN_DB, &img[..], img.len(), true)
        .map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA query_only=1;")
        .map_err(|e| e.to_string())?;
    conn.query_row("SELECT count(*) FROM sqlite_master", [], |r| {
        r.get::<_, i64>(0)
    })
    .map_err(|e| e.to_string())?;
    Ok(Db { conn })
}

impl Db {
    pub fn conn(&self) -> &rusqlite::Connection {
        &self.conn
    }

    /// User tables plus `sqlite_sequence` / `sqlite_stat1`. Tables whose metadata fails are kept with `error`.
    pub fn tables(&self) -> Vec<TableInfo> {
        let names: Vec<(String, String)> = match self.conn.prepare(
            "SELECT name, coalesce(sql,'') FROM sqlite_master WHERE type='table' ORDER BY name",
        ) {
            Ok(mut st) => st
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .map(|it| it.filter_map(Result::ok).collect())
                .unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        names
            .into_iter()
            .filter(|(n, _)| {
                !n.starts_with("sqlite_") || n == "sqlite_sequence" || n == "sqlite_stat1"
            })
            .map(|(name, sql)| self.table_info(&name, &sql))
            .collect()
    }

    fn table_info(&self, name: &str, sql: &str) -> TableInfo {
        let upper = sql.to_ascii_uppercase();
        let tail = upper.rsplit(')').next().unwrap_or("");
        let words: Vec<&str> = tail
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter(|w| !w.is_empty())
            .collect();
        let without_rowid = words
            .windows(2)
            .any(|w| w[0] == "WITHOUT" && w[1] == "ROWID");
        let mut info = TableInfo {
            name: name.to_string(),
            columns: Vec::new(),
            without_rowid,
            pk_cols: Vec::new(),
            rowid_alias: None,
            error: None,
        };
        let cols: Result<Vec<(String, i64, i64)>, String> = (|| {
            let mut st = self
                .conn
                .prepare(&format!("PRAGMA table_xinfo({})", quote(name)))
                .map_err(|e| e.to_string())?;
            let it = st
                .query_map([], |r| {
                    Ok((
                        r.get::<_, String>(1)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, i64>(6)?,
                    ))
                })
                .map_err(|e| e.to_string())?;
            it.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
        })();
        let cols = match cols {
            Ok(c) if !c.is_empty() => c,
            Ok(_) => {
                info.error = Some("no column metadata".into());
                return info;
            }
            Err(e) => {
                info.error = Some(e);
                return info;
            }
        };
        // hidden: 0 normal, 1 virtual-table hidden (excluded), 2/3 generated (kept)
        let cols: Vec<(String, i64)> = cols
            .into_iter()
            .filter(|c| c.2 != 1)
            .map(|c| (c.0, c.1))
            .collect();
        let mut pk: Vec<(i64, usize)> = cols
            .iter()
            .enumerate()
            .filter(|(_, c)| c.1 > 0)
            .map(|(i, c)| (c.1, i))
            .collect();
        pk.sort();
        info.pk_cols = pk.into_iter().map(|p| p.1).collect();
        if !without_rowid {
            info.rowid_alias = ["rowid", "_rowid_", "oid"]
                .iter()
                .find(|a| !cols.iter().any(|c| c.0.eq_ignore_ascii_case(a)))
                .map(|a| a.to_string());
        }
        info.columns = cols.into_iter().map(|c| c.0).collect();
        info
    }

    pub fn rows(&self, t: &TableInfo) -> Result<Rows, String> {
        if let Some(e) = &t.error {
            return Err(e.clone());
        }
        let cols = t
            .columns
            .iter()
            .map(|c| quote(c))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = match &t.rowid_alias {
            Some(a) => format!("SELECT {a}, {cols} FROM {}", quote(&t.name)),
            None => format!("SELECT {cols} FROM {}", quote(&t.name)),
        };
        let mut st = self.conn.prepare(&sql).map_err(|e| e.to_string())?;
        let n = t.columns.len();
        let off = usize::from(t.rowid_alias.is_some());
        let mut out = Vec::new();
        let mut rows = st.query([]).map_err(|e| e.to_string())?;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            let mut vals = Vec::with_capacity(n);
            for i in 0..n {
                vals.push(val(r.get_ref(i + off).map_err(|e| e.to_string())?));
            }
            let key = if off == 1 {
                RowKey::Rowid(r.get::<_, i64>(0).map_err(|e| e.to_string())?)
            } else if !t.pk_cols.is_empty() {
                RowKey::Pk(
                    t.pk_cols
                        .iter()
                        .filter_map(|&i| vals.get(i).cloned())
                        .collect(),
                )
            } else {
                RowKey::Full(vals.clone())
            };
            out.push((key, vals));
        }
        Ok(out)
    }
}
