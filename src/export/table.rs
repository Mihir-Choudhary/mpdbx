//! CSV / JSON writers and whole-case export (spec §10).
use super::guard::{GuardError, OutputGuard};
use crate::case::Case;
use crate::views::{VIEW_NAMES, View, build_view, prov_cols, raw_view, strength_label};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Names of every raw value present in the view, in first-seen order.
fn raw_names(v: &View) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for r in &v.rows {
        for (k, _) in &r.raw {
            if !names.contains(k) {
                names.push(k.clone());
            }
        }
    }
    names
}

/// UTF-8 with BOM; display columns, then `raw_*` columns, then provenance columns (RFC 4180 quoting).
pub fn write_csv(v: &View, w: &mut dyn Write) -> io::Result<()> {
    let raws = raw_names(v);
    let mut header: Vec<String> = v.columns.clone();
    header.extend(raws.iter().map(|r| format!("raw_{r}")));
    header.extend(["prov_source", "prov_key", "prov_status"].map(String::from));
    w.write_all("\u{feff}".as_bytes())?;
    writeln!(
        w,
        "{}",
        header
            .iter()
            .map(|h| csv_field(h))
            .collect::<Vec<_>>()
            .join(",")
    )?;
    for r in &v.rows {
        let mut cells: Vec<String> = r.cells.iter().map(|c| csv_field(c)).collect();
        for n in &raws {
            cells.push(csv_field(
                r.raw
                    .iter()
                    .find(|(k, _)| k == n)
                    .map(|(_, x)| x.as_str())
                    .unwrap_or(""),
            ));
        }
        let (s, k, st) = r.prov.as_ref().map(prov_cols).unwrap_or_default();
        cells.extend([csv_field(&s), csv_field(&k), csv_field(&st)]);
        writeln!(w, "{}", cells.join(","))?;
    }
    Ok(())
}

/// Array of `{display, raw, prov, links}`; every value is a string, so 64-bit integers never lose precision.
pub fn write_json(case: &Case, v: &View, w: &mut dyn Write) -> io::Result<()> {
    use serde_json::{Map, Value, json};
    let rows: Vec<Value> = v
        .rows
        .iter()
        .map(|r| {
            let display: Map<String, Value> = v.columns.iter().cloned().zip(r.cells.iter().map(|c| Value::String(c.clone()))).collect();
            let raw: Map<String, Value> = r.raw.iter().map(|(k, x)| (k.clone(), Value::String(x.clone()))).collect();
            let prov = r.prov.as_ref().map(prov_cols).map(|(s, k, st)| json!({"source": s, "key": k, "status": st})).unwrap_or(Value::Null);
            let links: Vec<Value> = r
                .node
                .and_then(|n| case.links_by_node.get(&n).map(|ls| (n, ls)))
                .map(|(n, ls)| {
                    ls.iter()
                        .map(|&i| {
                            let k = &case.links[i as usize];
                            let other = if k.a == n { k.b } else { k.a };
                            json!({"rule": k.rule, "strength": strength_label(k.strength), "note": k.note, "other": format!("{other:?}")})
                        })
                        .collect()
                })
                .unwrap_or_default();
            json!({"display": display, "raw": raw, "prov": prov, "links": links})
        })
        .collect();
    serde_json::to_writer_pretty(&mut *w, &rows).map_err(io::Error::other)?;
    writeln!(w)
}

/// Opens an export target without a check-then-truncate race: `create_new` when overwriting is not allowed;
/// otherwise open without truncation, verify the opened handle is not an evidence input, then truncate.
pub fn open_target(
    guard: &OutputGuard,
    path: &Path,
    force: bool,
) -> Result<std::fs::File, GuardError> {
    let io_err = |e: io::Error| GuardError::Io(e.to_string());
    if !force {
        return std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| match e.kind() {
                io::ErrorKind::AlreadyExists => GuardError::Exists,
                _ => io_err(e),
            });
    }
    let f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
        .map_err(io_err)?;
    match crate::evidence::handle_identity(&f) {
        Some(id) if guard.is_input_identity(id) => Err(GuardError::IsInput),
        Some(_) => {
            f.set_len(0).map_err(io_err)?;
            Ok(f)
        }
        None => Err(GuardError::Io(format!(
            "cannot identify {}",
            path.display()
        ))),
    }
}

fn write_file(
    guard: &OutputGuard,
    path: &Path,
    force: bool,
    f: impl FnOnce(&mut dyn Write) -> io::Result<()>,
) -> Result<(), GuardError> {
    let file = open_target(guard, path, force)?;
    let mut bw = io::BufWriter::new(file);
    f(&mut bw)
        .and_then(|_| bw.flush())
        .map_err(|e| GuardError::Io(e.to_string()))
}

/// Every typed view and every raw table into `dir` (created if missing). Nothing is written unless every
/// target passes the guard first, so a refusal leaves the directory untouched.
pub fn export_all(
    case: &Case,
    dir: &Path,
    json: bool,
    guard: &OutputGuard,
    force: bool,
) -> Result<Vec<PathBuf>, GuardError> {
    std::fs::create_dir_all(dir).map_err(|e| GuardError::Io(e.to_string()))?;
    let ext = if json { "json" } else { "csv" };
    let mut views: Vec<View> = VIEW_NAMES
        .iter()
        .map(|n| build_view(case, n, None))
        .collect();
    views.extend(case.raw.iter().map(|t| {
        let mut v = raw_view(case, &t.name);
        v.name = format!("raw_{}", t.name);
        v
    }));
    let mut targets: Vec<PathBuf> = Vec::new();
    let mut used: std::collections::HashSet<String> = std::collections::HashSet::new();
    for v in &views {
        // Sanitised names can collide ("a:b", "a?b", "A:B"): suffix _2, _3 … case-insensitively.
        let mut p = guard.child(dir, &format!("{}.{ext}", v.name))?;
        let mut n = 2;
        while !used.insert(
            p.file_name()
                .map(|f| f.to_string_lossy().to_lowercase())
                .unwrap_or_default(),
        ) {
            p = guard.child(dir, &format!("{}_{n}.{ext}", v.name))?;
            n += 1;
        }
        guard.check_file(&p, force)?;
        targets.push(p);
    }
    for (v, p) in views.iter().zip(&targets) {
        if json {
            write_file(guard, p, force, |w| write_json(case, v, w))?;
        } else {
            write_file(guard, p, force, |w| write_csv(v, w))?;
        }
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::tests::tmpdir;
    use crate::model::{Node, Prov};
    use crate::views::{View, ViewRow, tests::case};

    fn tiny() -> View {
        View {
            name: "T".into(),
            columns: vec!["A".into(), "B".into()],
            rows: vec![ViewRow {
                cells: vec!["x,y".into(), "say \"hi\"\nok".into()],
                raw: vec![("B".into(), "1125899906842624".into())],
                prov: Some(Prov::Store {
                    file: "F".into(),
                    section: 2,
                    offset: 4,
                }),
                node: Some(Node::Event(0)),
            }],
        }
    }

    #[test]
    fn csv_quotes_and_bom() {
        let mut out = Vec::new();
        write_csv(&tiny(), &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.starts_with('\u{feff}'));
        assert!(s.contains("\"x,y\",\"say \"\"hi\"\"\nok\""), "{s}");
        assert!(s.lines().next().unwrap().contains("raw_B"));
        assert!(s.contains("Store F §2@0x4"));
    }

    #[test]
    fn json_u64_as_string() {
        let c = case();
        let mut out = Vec::new();
        write_json(&c, &tiny(), &mut out).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(
            v[0]["raw"]["B"],
            serde_json::Value::String("1125899906842624".into())
        );
        assert_eq!(v[0]["display"]["A"], "x,y");
        assert!(v[0]["links"].is_array());
    }

    #[test]
    fn export_all_writes_views_and_raw_tables() {
        let c = case();
        let d = tmpdir("export_all");
        let g = OutputGuard::new(&c.inputs.iter().collect::<Vec<_>>());
        let files = export_all(&c, &d, false, &g, false).unwrap();
        assert!(files.iter().any(|f| f.ends_with("Timeline.csv")));
        assert!(
            files
                .iter()
                .any(|f| f.ends_with("raw_BackupProcessInfo.csv"))
        );
        assert!(
            export_all(&c, &d, false, &g, false).is_err(),
            "second run without force refuses to overwrite"
        );
        assert!(export_all(&c, &d, true, &g, true).is_ok());
    }

    #[test]
    fn sanitised_name_collisions_get_unique_files() {
        let mut c = (*case()).clone();
        for n in ["a:b", "a?b", "A:B"] {
            c.raw.push(crate::model::RawTable {
                name: n.into(),
                columns: vec!["x".into()],
                rows: vec![],
                readable: true,
            });
        }
        let d = tmpdir("export_names");
        let g = OutputGuard::new(&[]);
        let files = export_all(&c, &d, false, &g, false).unwrap();
        let mut lower: Vec<String> = files
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_lowercase())
            .collect();
        let n = lower.len();
        lower.sort();
        lower.dedup();
        assert_eq!(
            lower.len(),
            n,
            "every export file name is unique (case-insensitive)"
        );
    }

    #[test]
    fn open_target_never_truncates_without_force_or_an_input() {
        let d = tmpdir("export_toctou");
        // private evidence copy, so no parallel test holds it open
        std::fs::write(d.join("evidence.db"), b"evidence bytes").unwrap();
        let inp = crate::evidence::read_input(&d.join("evidence.db"), 1 << 20).unwrap();
        let g = OutputGuard::new(&[&inp]);
        std::fs::write(d.join("late.csv"), b"keep").unwrap();
        assert!(open_target(&g, &d.join("late.csv"), false).is_err());
        assert_eq!(std::fs::read(d.join("late.csv")).unwrap(), b"keep");
        std::fs::hard_link(d.join("evidence.db"), d.join("link.csv")).unwrap();
        assert_eq!(
            open_target(&g, &d.join("link.csv"), true).err(),
            Some(GuardError::IsInput)
        );
        assert_eq!(
            std::fs::read(d.join("evidence.db")).unwrap(),
            b"evidence bytes"
        );
    }

    #[test]
    fn export_all_refuses_input_dir_collision() {
        let c = case();
        let d = tmpdir("export_collide");
        let db = &c.inputs[0];
        std::fs::hard_link(&db.path, d.join("Timeline.csv")).unwrap();
        let before = std::fs::read(&db.path).unwrap();
        let g = OutputGuard::new(&c.inputs.iter().collect::<Vec<_>>());
        assert_eq!(
            export_all(&c, &d, false, &g, true),
            Err(GuardError::IsInput)
        );
        assert_eq!(std::fs::read(&db.path).unwrap(), before);
    }
}
