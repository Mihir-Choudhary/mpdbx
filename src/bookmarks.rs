//! Bookmarks/tags and natural keys that stay stable across reloads and snapshots (spec §8.2, §10).
use crate::case::Case;
use crate::export::guard::{GuardError, OutputGuard};
use crate::model::{Event, EventKind, Node, Prov};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::Path;

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Bookmark {
    /// `natural_key` of the bookmarked node.
    pub node: String,
    pub tag: String,
    pub note: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct Bookmarks {
    pub items: Vec<Bookmark>,
}

fn f<'a>(e: &'a Event, name: &str) -> &'a str {
    e.fields
        .iter()
        .find(|x| x.name == name)
        .map(|x| x.raw.as_str())
        .unwrap_or("")
}

fn path_key(c: &Case, e: &Event) -> String {
    e.location
        .and_then(|l| c.locations.get(l as usize))
        .map(|l| l.key.0.clone())
        .unwrap_or_default()
}

/// Per-kind natural key (spec §10): what identifies the same fact in another load or snapshot.
pub fn event_key(c: &Case, e: &Event) -> String {
    use EventKind::*;
    let t = e.time.map(|x| x.to_string()).unwrap_or_default();
    let p = path_key(c, e);
    let store = e
        .store
        .and_then(|s| c.store_files.get(s as usize))
        .cloned()
        .unwrap_or_default();
    let s = |x: &str| x.to_string();
    let parts: Vec<String> = match e.kind {
        ProcessFirstStart | ModuleFirstLoad | NoCertExec | OfnProcessed | LowFiHit => vec![p, t],
        FileContext => vec![p, s(f(e, "Context")), t],
        OfnSet | OfnSetInferred => vec![p, s(f(e, "OriginalFileName"))],
        QueueEntry => vec![s(f(e, "Queue")), s(f(e, "Key")), s(f(e, "InsertTime"))],
        FileScan | AmsiScan | StoreProcessStart | AmsiProcessStart => vec![store],
        StoreExpiry => vec![f(e, "PersistId (Store file name)").to_ascii_uppercase()],
        FileHashed => {
            let sha = c
                .contents
                .iter()
                .find(|x| x.event == e.id)
                .and_then(|x| {
                    x.digests
                        .iter()
                        .find(|d| d.0 == crate::model::DigestAlg::Sha256)
                })
                .map(|d| crate::decode::values::hex(&d.1))
                .unwrap_or_default();
            vec![s(f(e, "FileRef")), s(f(e, "Volume serial")), sha]
        }
        RegistryChange => vec![s(f(e, "RegPath")), t],
        RdpLogon => vec![s(f(e, "Source IP")), t],
        ScanRun => vec![s(f(e, "GUID")), t],
        BmRecord => match &e.prov {
            Prov::Db { table, key, .. } => vec![
                table.clone(),
                crate::decode::values::hex(&crate::provenance::key_bytes(key)),
            ],
            _ => vec![t],
        },
    };
    // JSON-encoded components: unambiguous whatever characters the values contain.
    format!(
        "event|{:?}|{}",
        e.kind,
        serde_json::to_string(&parts).unwrap_or_default()
    )
}

pub fn natural_key(c: &Case, n: Node) -> String {
    match n {
        Node::Event(i) => c
            .events
            .get(i as usize)
            .map(|e| event_key(c, e))
            .unwrap_or_default(),
        Node::Location(i) => format!(
            "location|{}",
            c.locations
                .get(i as usize)
                .map(|l| l.key.0.as_str())
                .unwrap_or("")
        ),
        Node::Run(i) => {
            let obs: Vec<_> = c
                .runs
                .get(i as usize)
                .map(|r| {
                    r.obs
                        .iter()
                        .filter_map(|&o| c.obs.get(o as usize))
                        .collect()
                })
                .unwrap_or_default();
            let start = obs
                .iter()
                .filter_map(|o| o.start)
                .min()
                .map(|t| t.to_string())
                .unwrap_or_default();
            let mut locs: Vec<String> = obs
                .iter()
                .filter_map(|o| o.location)
                .filter_map(|l| c.locations.get(l as usize))
                .map(|l| l.key.0.clone())
                .collect();
            locs.sort();
            locs.dedup();
            let mut pids: Vec<u32> = obs.iter().filter_map(|o| o.pid).collect();
            pids.sort();
            pids.dedup();
            format!(
                "run|{}",
                serde_json::to_string(&(start, locs, pids)).unwrap_or_default()
            )
        }
        Node::Content(i) => c
            .contents
            .get(i as usize)
            .map(|x| {
                let sha = x
                    .digests
                    .iter()
                    .find(|d| d.0 == crate::model::DigestAlg::Sha256)
                    .map(|d| crate::decode::values::hex(&d.1))
                    .unwrap_or_default();
                format!(
                    "content|{}|{}|{}|{sha}",
                    x.fileref.vsn, x.fileref.record, x.fileref.seq
                )
            })
            .unwrap_or_default(),
        Node::Store(i) => format!(
            "store|{}",
            c.store_files
                .get(i as usize)
                .map(|s| s.to_ascii_uppercase())
                .unwrap_or_default()
        ),
    }
}

/// Explicit "Save bookmarks". Replaces an existing file only with `overwrite` (after the user confirmed);
/// never an evidence input.
pub fn save(
    b: &Bookmarks,
    path: &Path,
    guard: &OutputGuard,
    overwrite: bool,
) -> Result<(), GuardError> {
    guard.check_file(path, overwrite)?;
    let mut f = crate::export::table::open_target(guard, path, overwrite)?;
    let s = serde_json::to_string_pretty(b).map_err(|e| GuardError::Io(e.to_string()))?;
    f.write_all(s.as_bytes())
        .map_err(|e| GuardError::Io(e.to_string()))
}

pub fn load(path: &Path) -> Result<Bookmarks, String> {
    let i = crate::evidence::read_input(path, 64 * 1024 * 1024)?;
    from_bytes(&i.bytes).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn from_bytes(b: &[u8]) -> Result<Bookmarks, String> {
    serde_json::from_slice(b).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Node;
    use crate::views::tests::case;

    #[test]
    fn bookmark_key_stable_across_reopen() {
        let (a, b) = (case(), case());
        for e in &a.events {
            assert_eq!(
                natural_key(&a, Node::Event(e.id)),
                natural_key(&b, Node::Event(e.id))
            );
        }
        assert!(natural_key(&a, Node::Event(0)).starts_with("event|"));
        let loc = natural_key(&a, Node::Location(0));
        assert!(loc.starts_with("location|"));
    }

    #[test]
    fn keys_are_unambiguous() {
        let mut c = (*case()).clone();
        let q = c
            .events
            .iter()
            .position(|e| e.kind == crate::model::EventKind::QueueEntry)
            .unwrap();
        let mut e2 = c.events[q].clone();
        let set = |e: &mut crate::model::Event, n: &str, v: &str| {
            e.fields.iter_mut().find(|f| f.name == n).unwrap().raw = v.into()
        };
        set(&mut c.events[q], "Queue", "a|b");
        set(&mut c.events[q], "Key", "c");
        set(&mut e2, "Queue", "a");
        set(&mut e2, "Key", "b|c");
        assert_ne!(event_key(&c, &c.events[q]), event_key(&c, &e2));
    }

    #[test]
    fn save_and_load_roundtrip_never_over_input() {
        let c = case();
        let d = crate::evidence::tests::tmpdir("bm_save");
        let b = Bookmarks {
            items: vec![Bookmark {
                node: natural_key(&c, Node::Event(1)),
                tag: "lead".into(),
                note: "check <this>".into(),
            }],
        };
        let g = crate::export::guard::OutputGuard::new(&c.inputs.iter().collect::<Vec<_>>());
        save(&b, &d.join("case.mpdbx.json"), &g, false).unwrap();
        assert_eq!(
            load(&d.join("case.mpdbx.json")).unwrap().items[0].note,
            "check <this>"
        );
        assert!(save(&b, &c.inputs[0].path, &g, true).is_err());
        std::fs::write(d.join("notes.json"), b"unrelated").unwrap();
        assert_eq!(
            save(&b, &d.join("notes.json"), &g, false),
            Err(crate::export::guard::GuardError::Exists)
        );
        assert_eq!(std::fs::read(d.join("notes.json")).unwrap(), b"unrelated");
        assert!(save(&b, &d.join("notes.json"), &g, true).is_ok());
    }
}
