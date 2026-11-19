//! Self-contained HTML report (spec §10): inline CSS, no script, no external resources.
use crate::bookmarks::{Bookmarks, natural_key};
use crate::case::Case;
use crate::decode::time::fmt_ft;
use crate::model::Node;
use crate::views::prov_cols;
use std::collections::BTreeMap;
use std::fmt::Write;

pub fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '&' => o.push_str("&amp;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c => o.push(c),
        }
    }
    o
}

const CSS: &str = "body{font:14px/1.45 'Segoe UI',system-ui,sans-serif;color:#1b2533;background:#f5f7fa;margin:0;padding:24px 16px}\
main{max-width:1180px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}h2{font-size:17px;margin:28px 0 8px;border-bottom:1px solid #d7dce4;padding-bottom:4px}\
.muted{color:#5b6b80}table{border-collapse:collapse;width:100%;background:#fff;border:1px solid #d7dce4;margin:6px 0}\
th,td{text-align:left;padding:4px 8px;border-bottom:1px solid #e8ecf2;vertical-align:top}th{background:#eef2f7;font-weight:600}\
td.m,.m{font-family:Consolas,'Cascadia Mono',monospace;font-size:12.5px;word-break:break-all}.flag{color:#b42318;font-weight:600}\
.note{background:#fff8e6}.wal{background:#fff4d6}";

/// Static §5.4 appendix: (rule, link, rule text, strength).
const RULES: &[(&str, &str, &str, &str)] = &[
    (
        "1",
        "Location ↔ observation",
        "equal normalised path (PathKey)",
        "● exact (◐/○ when a heuristic volume mapping was used)",
    ),
    (
        "2",
        "Digest ↔ file content",
        "same FileHashes row",
        "● exact",
    ),
    (
        "3",
        "File content ↔ location",
        "analyst-bound MFT CSV gives the path for (record, seq) on that volume serial",
        "● exact",
    ),
    (
        "4",
        "File content ↔ file content",
        "equal SHA256",
        "● exact",
    ),
    (
        "4b",
        "File content ↔ file content",
        "no SHA256 on one side and equal SHA1 (◐) or equal MD5 only (○); conflicting SHA256 never linked",
        "◐ / ○",
    ),
    (
        "P",
        "Process observations → run",
        "equal PID or path and start within ±1 ms; conflicting PIDs/paths never cluster; start-only matches are candidates only",
        "● / ○",
    ),
    (
        "5",
        "Store process start ↔ BPI first start",
        "same image path, start within ±1 ms",
        "● exact",
    ),
    (
        "5b",
        "Store process start ↔ BPI image",
        "same image path, different start: earlier/later run",
        "◐ partial",
    ),
    (
        "6",
        "No-cert execution ↔ BPI first start",
        "same path, first start 0–100 ms after insert, unique (else ≤ 1 s)",
        "● / ○",
    ),
    (
        "7",
        "AmsiFileCache ↔ Store record",
        "PersistId equals the Store file name; gives the ≈ scan-time estimate (expiry − 1 h)",
        "● exact",
    ),
    (
        "8",
        "Explicit foreign keys",
        "Bm* ID references; ThreatRecordId groups (unvalidated)",
        "● / ◐",
    ),
    (
        "9",
        "Tact queue entry → process run",
        "PID and ProcessStart from the queue name",
        "via P",
    ),
    (
        "10",
        "Time proximity",
        "analyst-chosen window, computed on demand",
        "○ heuristic",
    ),
];

fn row(cells: &[String]) -> String {
    format!(
        "<tr>{}</tr>",
        cells
            .iter()
            .map(|c| format!("<td>{c}</td>"))
            .collect::<String>()
    )
}

fn table(head: &[&str], rows: &[String]) -> String {
    format!(
        "<table><tr>{}</tr>{}</table>",
        head.iter()
            .map(|h| format!("<th>{}</th>", esc(h)))
            .collect::<String>(),
        rows.concat()
    )
}

fn m(s: &str) -> String {
    format!("<span class=\"m\">{}</span>", esc(s))
}

pub fn report(c: &Case, b: &Bookmarks) -> String {
    let tz = c.opts.tz;
    let ft = |t: Option<u64>| t.map(|x| fmt_ft(x, tz)).unwrap_or_default();
    let ev = &c.evidence;
    let mut h = String::new();
    let _ = write!(
        h,
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>mpdbx report</title><style>{CSS}</style></head><body><main><h1>MpEngineDB Explorer report</h1>\
<p class=\"muted\">mpdbx {} · times shown as {} · links show their rule and strength (● exact, ◐ partial, ○ heuristic)</p>",
        env!("CARGO_PKG_VERSION"),
        esc(&tz.suffix())
    );

    h.push_str("<h2>Evidence</h2>");
    let inputs: Vec<String> = ev
        .inputs
        .iter()
        .map(|i| {
            let mut notes = Vec::new();
            if i.changed_during_read {
                notes.push("changed while read");
            }
            if i.shared_write_fallback {
                notes.push("open for writing elsewhere");
            }
            row(&[
                m(&i.path),
                i.size.to_string(),
                m(&i.sha256),
                esc(&ft(i.mtime)),
                esc(&notes.join(", ")),
            ])
        })
        .collect();
    h.push_str(&table(
        &["Input", "Bytes", "SHA256", "Modified", "Notes"],
        &inputs,
    ));
    let w = &ev.wal;
    let facts = [
        (
            "Page size / pages",
            format!("{} / {}", ev.page_size, ev.pages),
        ),
        ("Encrypted", ev.encrypted.to_string()),
        ("Key", ev.key_source.clone()),
        (
            "Header bytes 18–19",
            format!("{:?} (loaded as rollback-journal copy)", ev.header_18_19),
        ),
        (
            "WAL present / header valid",
            format!("{} / {}", w.present, w.header_valid),
        ),
        (
            "WAL frames total / validated / applied",
            format!(
                "{} / {} / {}",
                w.frames_total, w.frames_valid, w.frames_applied
            ),
        ),
        ("WAL commits applied", w.commits.to_string()),
        (
            "WAL frames ignored after last commit",
            w.ignored_tail_frames.to_string(),
        ),
        (
            "WAL stop",
            w.stop
                .as_ref()
                .map(|s| format!("{s:?}"))
                .unwrap_or_else(|| "none (chain fully validated)".into()),
        ),
    ];
    h.push_str(&table(
        &["Fact", "Value"],
        &facts
            .iter()
            .map(|(k, v)| row(&[esc(k), esc(v)]))
            .collect::<Vec<_>>(),
    ));
    if !ev.warnings.is_empty() {
        let _ = write!(
            h,
            "<p><b>Warnings</b></p><ul>{}</ul>",
            ev.warnings
                .iter()
                .map(|x| format!("<li>{}</li>", esc(x)))
                .collect::<String>()
        );
    }

    h.push_str("<h2>Summary</h2>");
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for e in &c.events {
        *kinds.entry(format!("{:?}", e.kind)).or_default() += 1;
    }
    let mut rules: BTreeMap<&str, usize> = BTreeMap::new();
    for k in &c.links {
        *rules.entry(k.rule).or_default() += 1;
    }
    let mut srows: Vec<String> = kinds
        .iter()
        .map(|(k, n)| row(&[esc(k), n.to_string()]))
        .collect();
    srows.push(row(&["Locations".into(), c.locations.len().to_string()]));
    srows.push(row(&["Process runs".into(), c.runs.len().to_string()]));
    srows.extend(
        rules
            .iter()
            .map(|(r, n)| row(&[format!("Links by rule {}", esc(r)), n.to_string()])),
    );
    h.push_str(&table(&["Item", "Count"], &srows));

    h.push_str("<h2>Red flags</h2><p class=\"muted\">No-embedded-cert executions outside system dirs, executable renames, threat queue entries, RDP logons, rows that exist only in (or were removed by) the WAL.</p>");
    let flags: Vec<String> = c
        .events
        .iter()
        .filter(|e| e.flag)
        .map(|e| {
            let p = e
                .location
                .and_then(|l| c.locations.get(l as usize))
                .map(|l| l.spellings[0].clone())
                .unwrap_or_default();
            row(&[
                esc(&ft(e.time)),
                esc(&format!("{:?}", e.kind)),
                format!("<span class=\"flag\">{}</span>", esc(&e.summary)),
                m(&p),
                esc(&prov_cols(&e.prov).0),
                esc(&prov_cols(&e.prov).2),
            ])
        })
        .collect();
    let mut flags = flags;
    // WAL-only / WAL-removed rows that produced no event (e.g. InventoryState, unknown tables).
    let with_event: std::collections::HashSet<(String, Vec<u8>)> = c
        .events
        .iter()
        .filter_map(|e| match &e.prov {
            crate::model::Prov::Db { table, key, .. } => {
                Some((table.clone(), crate::provenance::key_bytes(key)))
            }
            _ => None,
        })
        .collect();
    for t in &c.raw {
        for (vals, p) in &t.rows {
            if let crate::model::Prov::Db {
                key,
                status: s @ (crate::model::DbStatus::WalOnly | crate::model::DbStatus::RemovedByWal),
                ..
            } = p
            {
                if with_event.contains(&(t.name.clone(), crate::provenance::key_bytes(key))) {
                    continue;
                }
                let summary = t
                    .columns
                    .iter()
                    .zip(vals)
                    .map(|(n, v)| {
                        format!("{n}={}", crate::correlate::load::decode_cell(n, v, tz).0)
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                flags.push(row(&[
                    String::new(),
                    esc(&format!("raw {}", t.name)),
                    format!("<span class=\"flag\">{}</span>", esc(&summary)),
                    String::new(),
                    esc(&crate::views::key_label(key)),
                    esc(crate::views::status_label(*s)),
                ]));
            }
        }
    }
    h.push_str(&table(
        &["Time", "Type", "Summary", "Path", "Source", "Status"],
        &flags,
    ));

    h.push_str("<h2>Bookmarked rows</h2>");
    let mut keyed: BTreeMap<String, Node> = BTreeMap::new();
    for e in &c.events {
        keyed
            .entry(natural_key(c, Node::Event(e.id)))
            .or_insert(Node::Event(e.id));
    }
    for l in &c.locations {
        keyed
            .entry(natural_key(c, Node::Location(l.id)))
            .or_insert(Node::Location(l.id));
    }
    for r in &c.runs {
        keyed
            .entry(natural_key(c, Node::Run(r.id)))
            .or_insert(Node::Run(r.id));
    }
    for x in &c.contents {
        keyed
            .entry(natural_key(c, Node::Content(x.id)))
            .or_insert(Node::Content(x.id));
    }
    for i in 0..c.store_files.len() as u32 {
        keyed
            .entry(natural_key(c, Node::Store(i)))
            .or_insert(Node::Store(i));
    }
    let brows: Vec<String> = b
        .items
        .iter()
        .map(|bm| {
            let what = match keyed.get(&bm.node) {
                Some(Node::Event(i)) => {
                    let e = &c.events[*i as usize];
                    format!("{} — {}", ft(e.time), e.summary)
                }
                Some(Node::Location(i)) => c.locations[*i as usize].spellings[0].clone(),
                Some(Node::Content(i)) => {
                    let x = &c.contents[*i as usize];
                    format!(
                        "file content MFT {} on {}",
                        crate::decode::values::fmt_fileref(&x.fileref),
                        crate::decode::values::fmt_vsn(x.fileref.vsn)
                    )
                }
                Some(Node::Store(i)) => format!("Store record {}", c.store_files[*i as usize]),
                Some(n) => format!("{n:?}"),
                None => "(not present in this case)".into(),
            };
            format!(
                "<tr class=\"note\"><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                esc(&bm.tag),
                esc(&what),
                esc(&bm.note),
                m(&bm.node)
            )
        })
        .collect();
    h.push_str(&table(&["Tag", "Row", "Note", "Key"], &brows));

    h.push_str("<h2>Link rules</h2>");
    let rr: Vec<String> = RULES
        .iter()
        .map(|(r, l, t, s)| row(&[format!("rule {}", esc(r)), esc(l), esc(t), esc(s)]))
        .collect();
    h.push_str(&table(&["Rule", "Link", "Rule", "Strength"], &rr));
    h.push_str("</main></body></html>\n");
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bookmarks::{Bookmark, Bookmarks, natural_key};
    use crate::model::{EventKind, Node};
    use crate::views::tests::case;

    #[test]
    fn report_escapes_html() {
        let mut c = (*case()).clone();
        c.events[0].summary = "<script>alert(1)</script> & co".into();
        c.events[0].flag = true;
        let html = report(&c, &Bookmarks::default());
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; co"));
        assert!(!html.contains("<script"));
    }

    #[test]
    fn report_resolves_content_bookmarks_and_raw_wal_rows() {
        let c = case();
        let b = Bookmarks {
            items: vec![Bookmark {
                node: natural_key(&c, Node::Content(0)),
                tag: "hash".into(),
                note: "n".into(),
            }],
        };
        let html = report(&c, &b);
        assert!(!html.contains("(not present in this case)"));
        assert!(
            html.contains("raw InventoryState"),
            "WAL-only row without an event belongs in red flags"
        );
    }

    #[test]
    fn report_no_external_refs() {
        let html = report(&case(), &Bookmarks::default());
        assert!(!html.to_lowercase().contains("http"));
        assert!(!html.contains("<script"));
        assert!(html.starts_with("<!doctype html>"));
    }

    #[test]
    fn report_lists_red_flags_bookmarks_and_evidence() {
        let c = case();
        let nc = c
            .events
            .iter()
            .find(|e| e.kind == EventKind::NoCertExec)
            .unwrap();
        let b = Bookmarks {
            items: vec![Bookmark {
                node: natural_key(&c, Node::Event(nc.id)),
                tag: "lead".into(),
                note: "analyst note 42".into(),
            }],
        };
        let html = report(&c, &b);
        assert!(html.contains("analyst note 42"));
        assert!(html.contains(&crate::export::report::esc(&nc.summary)));
        assert!(html.contains(&c.evidence.inputs[0].sha256));
        assert!(html.contains("Red flags"));
        assert!(html.contains("rule 6"));
    }
}
