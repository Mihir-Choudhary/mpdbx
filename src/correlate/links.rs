//! Link rules 1–9 and process-run clustering (rule P) (spec §5.4).
//! Strength of a link = min(rule strength, strength of any heuristic path mapping it relied on).
use crate::correlate::load::Loaded;
use crate::model::{DigestAlg, EventKind, Location, Node, Strength};
pub use crate::model::{Link, ProcessRun};
use crate::normalize::path::{PathKey, key_of, loc_class, parse_path};
use std::collections::{HashMap, HashSet};

/// 1 ms in FILETIME ticks.
const MS: u64 = 10_000;
const RULE6_EXACT: u64 = 100 * MS;
const RULE6_MAX: u64 = 1_000 * MS;
const HOUR: u64 = 36_000_000_000;

/// MFTECmd `$MFT` CSV bound by the analyst to one volume serial and drive letter.
#[derive(Clone, Debug, Default)]
pub struct MftIndex {
    pub vsn: u32,
    pub drive: char,
    /// (record, seq) → every name (hard links) as `X:\…`
    pub by_ref: HashMap<(u64, u16), Vec<String>>,
    /// Rows missing required fields or with non-numeric references.
    pub skipped: u32,
}

fn csv_records(text: &str) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut row = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quoted, c) {
            (true, '"') if chars.peek() == Some(&'"') => {
                field.push('"');
                chars.next();
            }
            (true, '"') => quoted = false,
            (true, c) => field.push(c),
            (false, '"') if field.is_empty() => quoted = true,
            (false, ',') => row.push(std::mem::take(&mut field)),
            (false, '\r') => {}
            (false, '\n') => {
                row.push(std::mem::take(&mut field));
                rows.push(std::mem::take(&mut row));
            }
            (false, c) => field.push(c),
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

/// Columns are found by header name: `EntryNumber, SequenceNumber, ParentPath, FileName`.
pub fn load_mft_csv(bytes: &[u8], vsn: u32, drive: char) -> Result<MftIndex, String> {
    let text = String::from_utf8_lossy(bytes);
    let text = text.trim_start_matches('\u{feff}');
    let mut recs = csv_records(text).into_iter();
    let header = recs.next().ok_or("empty CSV")?;
    let col = |n: &str| {
        header
            .iter()
            .position(|h| h.trim().eq_ignore_ascii_case(n))
            .ok_or(format!("CSV lacks column {n}"))
    };
    let (ce, cs, cp, cf) = (
        col("EntryNumber")?,
        col("SequenceNumber")?,
        col("ParentPath")?,
        col("FileName")?,
    );
    let drive = drive.to_ascii_uppercase();
    let mut idx = MftIndex {
        vsn,
        drive,
        by_ref: HashMap::new(),
        skipped: 0,
    };
    let need = ce.max(cs).max(cp).max(cf);
    for r in recs {
        if r.len() <= need || r[cf].is_empty() {
            idx.skipped += 1;
            continue;
        }
        let (Ok(rec), Ok(seq)) = (r[ce].trim().parse::<u64>(), r[cs].trim().parse::<u16>()) else {
            idx.skipped += 1;
            continue;
        };
        // MFTECmd ParentPath is volume-relative: "." or ".\dir\…". Only that prefix is removed; names are kept verbatim.
        let parent = match r[cp].as_str() {
            "." => "",
            p => p.strip_prefix(".\\").unwrap_or(p),
        };
        let name = &r[cf];
        let path = if parent.is_empty() {
            format!("{drive}:\\{name}")
        } else {
            format!("{drive}:\\{parent}\\{name}")
        };
        idx.by_ref.entry((rec, seq)).or_default().push(path);
    }
    Ok(idx)
}

fn nk(n: Node) -> (u8, u32) {
    match n {
        Node::Event(i) => (0, i),
        Node::Location(i) => (1, i),
        Node::Run(i) => (2, i),
        Node::Content(i) => (3, i),
        Node::Store(i) => (4, i),
    }
}

struct Out {
    links: Vec<Link>,
    seen: HashSet<((u8, u32), (u8, u32))>,
}

impl Out {
    fn add(
        &mut self,
        a: Node,
        b: Node,
        rule: &'static str,
        strength: Strength,
        note: impl Into<String>,
    ) {
        let (x, y) = (nk(a), nk(b));
        let key = if x <= y { (x, y) } else { (y, x) };
        if a == b || !self.seen.insert(key) {
            return;
        }
        self.links.push(Link {
            a,
            b,
            rule,
            strength,
            note: note.into(),
        });
    }
}

struct Uf {
    parent: Vec<usize>,
}

impl Uf {
    fn find(&mut self, x: usize) -> usize {
        let mut r = x;
        while self.parent[r] != r {
            r = self.parent[r];
        }
        let mut c = x;
        while self.parent[c] != r {
            let n = self.parent[c];
            self.parent[c] = r;
            c = n;
        }
        r
    }
}

fn loc_strength(l: &Loaded, loc: Option<u32>) -> Strength {
    loc.and_then(|i| l.locations.get(i as usize))
        .map(|x| x.key_strength)
        .unwrap_or(Strength::Exact)
}

fn conflicts(a: &HashSet<u32>, b: &HashSet<u32>) -> bool {
    !a.is_empty() && !b.is_empty() && a.is_disjoint(b)
}

fn digest(l: &Loaded, c: usize, alg: DigestAlg) -> Option<&Vec<u8>> {
    l.contents[c]
        .digests
        .iter()
        .find(|d| d.0 == alg)
        .map(|d| &d.1)
}

pub fn link(l: &mut Loaded, mft: Option<&MftIndex>) -> (Vec<Link>, Vec<ProcessRun>) {
    let mut out = Out {
        links: Vec::new(),
        seen: HashSet::new(),
    };

    // Rule 1: location ↔ each event observed there.
    for loc in &l.locations {
        for &e in &loc.events {
            out.add(
                Node::Location(loc.id),
                Node::Event(e),
                "1",
                Strength::Exact.min(loc.key_strength),
                "same path",
            );
        }
    }
    // Rule 2: digests ↔ their FileHashes row.
    for c in &l.contents {
        out.add(
            Node::Content(c.id),
            Node::Event(c.event),
            "2",
            Strength::Exact,
            "same FileHashes row",
        );
    }
    // Rule 3: FileRef → path through the bound MFT CSV.
    if let Some(m) = mft {
        let mut index: HashMap<PathKey, u32> =
            l.locations.iter().map(|x| (x.key.clone(), x.id)).collect();
        for ci in 0..l.contents.len() {
            let fr = l.contents[ci].fileref;
            if fr.vsn != m.vsn {
                continue;
            }
            for path in m
                .by_ref
                .get(&(fr.record, fr.seq))
                .cloned()
                .unwrap_or_default()
            {
                let p = parse_path(&path);
                let (key, st) = key_of(&p, &l.volmap);
                let id = *index.entry(key.clone()).or_insert_with(|| {
                    let id = l.locations.len() as u32;
                    l.locations.push(Location {
                        id,
                        key,
                        spellings: vec![path.clone()],
                        events: vec![],
                        class: loc_class(&p, &l.volmap),
                        key_strength: st,
                    });
                    id
                });
                let st = st.min(l.locations[id as usize].key_strength);
                out.add(
                    Node::Content(ci as u32),
                    Node::Location(id),
                    "3",
                    Strength::Exact.min(st),
                    "MFT CSV: path as of MFT acquisition",
                );
            }
        }
    }
    // Rules 4 / 4b: same content.
    let n = l.contents.len();
    for a in 0..n {
        for b in a + 1..n {
            let (s_a, s_b) = (
                digest(l, a, DigestAlg::Sha256),
                digest(l, b, DigestAlg::Sha256),
            );
            let (a_n, b_n) = (Node::Content(a as u32), Node::Content(b as u32));
            if let (Some(x), Some(y)) = (s_a, s_b) {
                if x == y {
                    out.add(a_n, b_n, "4", Strength::Exact, "equal SHA256");
                }
                continue; // both have SHA256: equal → linked, different → never merged
            }
            let (h_a, h_b) = (digest(l, a, DigestAlg::Sha1), digest(l, b, DigestAlg::Sha1));
            if let (Some(x), Some(y)) = (h_a, h_b) {
                if x == y {
                    out.add(
                        a_n,
                        b_n,
                        "4b",
                        Strength::Partial,
                        "equal SHA1 (no SHA256 on one side)",
                    );
                }
                continue;
            }
            if let (Some(x), Some(y)) = (digest(l, a, DigestAlg::Md5), digest(l, b, DigestAlg::Md5))
            {
                if x == y {
                    out.add(a_n, b_n, "4b", Strength::Heuristic, "equal MD5 only");
                }
            }
        }
    }

    // Rule P: cluster process observations.
    let m = l.obs.len();
    let mut uf = Uf {
        parent: (0..m).collect(),
    };
    let mut pids: Vec<HashSet<u32>> = l.obs.iter().map(|o| o.pid.into_iter().collect()).collect();
    let mut locs: Vec<HashSet<u32>> = l
        .obs
        .iter()
        .map(|o| o.location.into_iter().collect())
        .collect();
    let mut by_start: Vec<usize> = (0..m).filter(|&i| l.obs[i].start.is_some()).collect();
    by_start.sort_by_key(|&i| l.obs[i].start);
    let window = |i: usize, j: usize, l: &Loaded| {
        let (a, b) = (l.obs[i].start.unwrap_or(0), l.obs[j].start.unwrap_or(0));
        a.abs_diff(b) <= MS
    };
    let mut candidates = Vec::new();
    for (k, &i) in by_start.iter().enumerate() {
        for &j in &by_start[k + 1..] {
            if !window(i, j, l) {
                break;
            }
            candidates.push((i, j));
        }
    }
    for &(i, j) in &candidates {
        let (oi, oj) = (&l.obs[i], &l.obs[j]);
        let pid_eq = oi.pid.is_some() && oi.pid == oj.pid;
        let loc_eq = oi.location.is_some() && oi.location == oj.location;
        if !(pid_eq || loc_eq) {
            continue;
        }
        let (ri, rj) = (uf.find(i), uf.find(j));
        if ri == rj || conflicts(&pids[ri], &pids[rj]) || conflicts(&locs[ri], &locs[rj]) {
            continue;
        }
        uf.parent[rj] = ri;
        let (p, q) = (std::mem::take(&mut pids[rj]), std::mem::take(&mut locs[rj]));
        pids[ri].extend(p);
        locs[ri].extend(q);
    }
    for &(i, j) in &candidates {
        let (ri, rj) = (uf.find(i), uf.find(j));
        if ri == rj || conflicts(&pids[ri], &pids[rj]) || conflicts(&locs[ri], &locs[rj]) {
            continue;
        }
        let st = Strength::Heuristic;
        out.add(
            Node::Event(l.obs[i].event),
            Node::Event(l.obs[j].event),
            "P",
            st,
            "start time only (±1 ms)",
        );
    }
    let mut run_of_root: HashMap<usize, u32> = HashMap::new();
    let mut runs: Vec<ProcessRun> = Vec::new();
    for i in 0..m {
        let r = uf.find(i);
        let id = *run_of_root.entry(r).or_insert_with(|| {
            runs.push(ProcessRun {
                id: runs.len() as u32,
                obs: vec![],
            });
            (runs.len() - 1) as u32
        });
        runs[id as usize].obs.push(i as u32);
        let o = &l.obs[i];
        let st = Strength::Exact.min(loc_strength(l, o.location));
        if l.events[o.event as usize].kind == EventKind::QueueEntry {
            out.add(
                Node::Run(id),
                Node::Event(o.event),
                "9",
                st,
                "Tact queue PID/ProcessStart → process run",
            );
        } else {
            out.add(
                Node::Run(id),
                Node::Event(o.event),
                "P",
                st,
                "same process run (PID or path, start ±1 ms)",
            );
        }
    }

    // Rules 5 / 5b: Store process start ↔ BPI first start.
    let kind_of = |l: &Loaded, o: usize| l.events[l.obs[o].event as usize].kind;
    let store_obs: Vec<usize> = (0..m)
        .filter(|&o| kind_of(l, o) == EventKind::StoreProcessStart)
        .collect();
    let bpi_obs: Vec<usize> = (0..m)
        .filter(|&o| kind_of(l, o) == EventKind::ProcessFirstStart)
        .collect();
    for &s in &store_obs {
        for &b in &bpi_obs {
            let (os, ob) = (&l.obs[s], &l.obs[b]);
            if os.location.is_none() || os.location != ob.location {
                continue;
            }
            let (Some(ts), Some(tb)) = (os.start, ob.start) else {
                continue;
            };
            let st = loc_strength(l, os.location);
            let (es, eb) = (Node::Event(os.event), Node::Event(ob.event));
            if ts.abs_diff(tb) <= MS {
                out.add(
                    es,
                    eb,
                    "5",
                    Strength::Exact.min(st),
                    "Store process start = BPI first start (±1 ms)",
                );
            } else if ts > tb + MS {
                out.add(
                    es,
                    eb,
                    "5b",
                    Strength::Partial.min(st),
                    "same image, later run",
                );
            } else if ts + MS < tb {
                out.add(
                    es,
                    eb,
                    "5b",
                    Strength::Partial.min(st),
                    "same image, earlier run (BPI predates or rolled over)",
                );
            }
        }
    }

    // Rule 6: no-cert execution ↔ BPI first start at the same location.
    let nocert: Vec<usize> = l
        .events
        .iter()
        .filter(|e| e.kind == EventKind::NoCertExec)
        .map(|e| e.id as usize)
        .collect();
    for ni in nocert {
        let (Some(loc), Some(ins)) = (l.events[ni].location, l.events[ni].time) else {
            continue;
        };
        let cands: Vec<(usize, u64)> = bpi_obs
            .iter()
            .filter(|&&b| l.obs[b].location == Some(loc))
            .filter_map(|&b| {
                l.obs[b]
                    .start
                    .and_then(|t| t.checked_sub(ins))
                    .filter(|d| *d <= RULE6_MAX)
                    .map(|d| (b, d))
            })
            .collect();
        let close: Vec<&(usize, u64)> = cands.iter().filter(|c| c.1 <= RULE6_EXACT).collect();
        let st = loc_strength(l, Some(loc));
        for &(b, d) in &cands {
            let exact = close.len() == 1 && close[0].0 == b;
            let strength = if exact {
                Strength::Exact.min(st)
            } else {
                Strength::Heuristic
            };
            let note = format!(
                "same path, first start {:.1} ms after no-cert insert",
                d as f64 / MS as f64
            );
            out.add(
                Node::Event(ni as u32),
                Node::Event(l.obs[b].event),
                "6",
                strength,
                note,
            );
        }
    }

    // Rule 7: AmsiFileCache PersistId ↔ Store record; sets the heuristic scan-time estimate.
    let store_idx: HashMap<String, u32> = l
        .store_files
        .iter()
        .enumerate()
        .map(|(i, f)| (f.to_ascii_lowercase(), i as u32))
        .collect();
    for ei in 0..l.events.len() {
        if l.events[ei].kind != EventKind::StoreExpiry {
            continue;
        }
        let pid = l.events[ei]
            .fields
            .iter()
            .find(|f| f.name.starts_with("PersistId"))
            .map(|f| f.display.to_ascii_lowercase());
        let Some(&si) = pid.as_ref().and_then(|p| store_idx.get(p)) else {
            continue;
        };
        out.add(
            Node::Event(ei as u32),
            Node::Store(si),
            "7",
            Strength::Exact,
            "PersistId = Store file name",
        );
        l.events[ei].store = Some(si);
        if let Some(exp) = l.events[ei].time {
            for e in l.events.iter_mut().filter(|e| {
                e.store == Some(si) && matches!(e.kind, EventKind::FileScan | EventKind::AmsiScan)
            }) {
                if e.time.is_none() {
                    e.time = exp.checked_sub(HOUR);
                    e.time_note = Some("≈ cache expiry − 1 h (rule 7, heuristic)".into());
                }
            }
        }
    }

    // Rule 8: explicit foreign keys between Bm* rows (by their ID column), ThreatRecordId groups.
    rule8(l, &mut out);

    (out.links, runs)
}

fn bm_field<'a>(e: &'a crate::model::Event, name: &str) -> Option<&'a str> {
    e.fields
        .iter()
        .find(|f| f.name == name)
        .map(|f| f.raw.as_str())
        .filter(|v| !v.is_empty() && *v != "0")
}

fn table_of(e: &crate::model::Event) -> Option<&str> {
    match &e.prov {
        crate::model::Prov::Db { table, .. } => Some(table),
        _ => None,
    }
}

fn rule8(l: &Loaded, out: &mut Out) {
    let by_id = |table: &str| -> HashMap<String, u32> {
        l.events
            .iter()
            .filter(|e| table_of(e) == Some(table))
            .filter_map(|e| bm_field(e, "ID").map(|id| (id.to_string(), e.id)))
            .collect()
    };
    for (child, fk, parent) in [
        ("BmFileActions", "FileInfoId", "BmFileInfo"),
        ("BmHipsRuleInfo", "ProcessInfoId", "BmProcessInfo"),
    ] {
        let parents = by_id(parent);
        for e in l.events.iter().filter(|e| table_of(e) == Some(child)) {
            if let Some(p) = bm_field(e, fk).and_then(|v| parents.get(v)) {
                out.add(
                    Node::Event(e.id),
                    Node::Event(*p),
                    "8",
                    Strength::Exact,
                    format!("{child}.{fk} → {parent}.ID"),
                );
            }
        }
    }
    // Only the relations named in §5.4 rule 8.
    let threat_cols: &[(&str, &str)] = &[
        ("BmFileActions", "ThreatRecordId"),
        ("BmFileStartupActions", "FdrThreatRecordId"),
        ("BmFileStartupActions", "EvaluatorThreatRecordId"),
        ("BmFileStartupActions", "TrustedInstallerThreatRecordId"),
        ("BmFileStartupActions", "LFRThreatRecordId"),
    ];
    let mut groups: HashMap<String, Vec<u32>> = HashMap::new();
    for e in &l.events {
        for (t, c) in threat_cols {
            if table_of(e) != Some(t) {
                continue;
            }
            if let Some(v) = bm_field(e, c) {
                groups.entry(v.to_string()).or_default().push(e.id);
            }
        }
    }
    let mut keys: Vec<_> = groups.keys().cloned().collect();
    keys.sort();
    for k in keys {
        let ids = &groups[&k];
        for w in ids.windows(2) {
            out.add(
                Node::Event(w[0]),
                Node::Event(w[1]),
                "8",
                Strength::Partial,
                format!("same ThreatRecordId {k} (unvalidated)"),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlate::load::Loaded;
    use crate::model::{
        DigestAlg, Event, EventKind, Field, FileContent, FileRef, LocClass, Location, Node,
        ProcessObs, Prov, Strength,
    };
    use crate::normalize::path::PathKey;

    const T: u64 = 134369015368153546;
    const MS: u64 = 10_000;

    fn ev(l: &mut Loaded, kind: EventKind, time: Option<u64>, loc: Option<u32>) -> u32 {
        let id = l.events.len() as u32;
        l.events.push(Event {
            id,
            kind,
            time,
            time_note: None,
            summary: String::new(),
            location: loc,
            obs: None,
            content: None,
            store: None,
            fields: vec![],
            prov: Prov::Store {
                file: String::new(),
                section: 2,
                offset: 0,
            },
            flag: false,
        });
        if let Some(x) = loc {
            l.locations[x as usize].events.push(id);
        }
        id
    }

    fn loc(l: &mut Loaded, key: &str, st: Strength) -> u32 {
        let id = l.locations.len() as u32;
        l.locations.push(Location {
            id,
            key: PathKey(key.into()),
            spellings: vec![],
            events: vec![],
            class: LocClass::Unknown,
            key_strength: st,
        });
        id
    }

    fn obs(
        l: &mut Loaded,
        kind: EventKind,
        loc: Option<u32>,
        pid: Option<u32>,
        start: Option<u64>,
    ) -> u32 {
        let e = ev(l, kind, start, loc);
        let id = l.obs.len() as u32;
        l.obs.push(ProcessObs {
            id,
            location: loc,
            pid,
            start,
            event: e,
        });
        l.events[e as usize].obs = Some(id);
        e
    }

    fn has(links: &[Link], a: Node, b: Node, rule: &str) -> Option<Strength> {
        links
            .iter()
            .find(|k| k.rule == rule && ((k.a == a && k.b == b) || (k.a == b && k.b == a)))
            .map(|k| k.strength)
    }

    #[test]
    fn p_pid_and_start_cluster() {
        let mut l = Loaded::default();
        obs(
            &mut l,
            EventKind::StoreProcessStart,
            None,
            Some(4120),
            Some(T),
        );
        obs(
            &mut l,
            EventKind::QueueEntry,
            None,
            Some(4120),
            Some(T + MS / 2),
        );
        let (_, runs) = link(&mut l, None);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].obs.len(), 2);
    }

    #[test]
    fn p_conflicting_pid_never_clusters() {
        let mut l = Loaded::default();
        let a = loc(&mut l, r"C:\A.EXE", Strength::Exact);
        obs(
            &mut l,
            EventKind::StoreProcessStart,
            Some(a),
            Some(1),
            Some(T),
        );
        obs(
            &mut l,
            EventKind::AmsiProcessStart,
            Some(a),
            Some(2),
            Some(T),
        );
        let (_, runs) = link(&mut l, None);
        assert_eq!(runs.len(), 2);
    }

    #[test]
    fn p_start_only_is_heuristic_link() {
        let mut l = Loaded::default();
        let a = loc(&mut l, r"C:\A.EXE", Strength::Exact);
        let e1 = obs(&mut l, EventKind::ProcessFirstStart, Some(a), None, Some(T));
        let e2 = obs(&mut l, EventKind::QueueEntry, None, Some(9), Some(T));
        let (links, runs) = link(&mut l, None);
        assert_eq!(runs.len(), 2);
        assert_eq!(
            has(&links, Node::Event(e1), Node::Event(e2), "P"),
            Some(Strength::Heuristic)
        );
    }

    #[test]
    fn r5_exact_and_5b_earlier_later() {
        let mut l = Loaded::default();
        let a = loc(&mut l, r"C:\A.EXE", Strength::Exact);
        let bpi = obs(&mut l, EventKind::ProcessFirstStart, Some(a), None, Some(T));
        let same = obs(
            &mut l,
            EventKind::StoreProcessStart,
            Some(a),
            Some(5),
            Some(T),
        );
        let later = obs(
            &mut l,
            EventKind::StoreProcessStart,
            Some(a),
            Some(6),
            Some(T + 1000 * MS),
        );
        let earlier = obs(
            &mut l,
            EventKind::StoreProcessStart,
            Some(a),
            Some(7),
            Some(T - 1000 * MS),
        );
        let (links, _) = link(&mut l, None);
        assert_eq!(
            has(&links, Node::Event(same), Node::Event(bpi), "5"),
            Some(Strength::Exact)
        );
        let k = links
            .iter()
            .find(|k| k.rule == "5b" && (k.a == Node::Event(later) || k.b == Node::Event(later)))
            .unwrap();
        assert!(k.note.contains("later run"));
        assert_eq!(k.strength, Strength::Partial);
        let k = links
            .iter()
            .find(|k| {
                k.rule == "5b" && (k.a == Node::Event(earlier) || k.b == Node::Event(earlier))
            })
            .unwrap();
        assert!(k.note.contains("earlier run"));
    }

    #[test]
    fn r6_100ms_exact_1s_heuristic_two_candidates_heuristic() {
        let mut l = Loaded::default();
        let a = loc(&mut l, r"C:\A.EXE", Strength::Exact);
        let b = loc(&mut l, r"C:\B.EXE", Strength::Exact);
        let c = loc(&mut l, r"C:\C.EXE", Strength::Exact);
        let ba = obs(&mut l, EventKind::ProcessFirstStart, Some(a), None, Some(T));
        let na = ev(&mut l, EventKind::NoCertExec, Some(T - 6 * MS), Some(a));
        let bb = obs(&mut l, EventKind::ProcessFirstStart, Some(b), None, Some(T));
        let nb = ev(&mut l, EventKind::NoCertExec, Some(T - 500 * MS), Some(b));
        let c1 = obs(&mut l, EventKind::ProcessFirstStart, Some(c), None, Some(T));
        let c2 = obs(
            &mut l,
            EventKind::ProcessFirstStart,
            Some(c),
            None,
            Some(T + 20 * MS),
        );
        let nc = ev(&mut l, EventKind::NoCertExec, Some(T - 10 * MS), Some(c));
        let (links, _) = link(&mut l, None);
        assert_eq!(
            has(&links, Node::Event(na), Node::Event(ba), "6"),
            Some(Strength::Exact)
        );
        assert_eq!(
            has(&links, Node::Event(nb), Node::Event(bb), "6"),
            Some(Strength::Heuristic)
        );
        assert_eq!(
            has(&links, Node::Event(nc), Node::Event(c1), "6"),
            Some(Strength::Heuristic)
        );
        assert_eq!(
            has(&links, Node::Event(nc), Node::Event(c2), "6"),
            Some(Strength::Heuristic)
        );
    }

    #[test]
    fn r7_sets_scan_estimate() {
        let mut l = Loaded::default();
        l.store_files
            .push("0123456789ABCDEF0123456789ABCDEF".into());
        let scan = ev(&mut l, EventKind::FileScan, None, None);
        l.events[scan as usize].store = Some(0);
        let exp = ev(&mut l, EventKind::StoreExpiry, Some(T), None);
        l.events[exp as usize].fields.push(Field {
            name: "PersistId (Store file name)".into(),
            display: "0123456789abcdef0123456789abcdef".into(),
            raw: String::new(),
        });
        let (links, _) = link(&mut l, None);
        assert_eq!(
            has(&links, Node::Event(exp), Node::Store(0), "7"),
            Some(Strength::Exact)
        );
        assert_eq!(l.events[scan as usize].time, Some(T - 36_000_000_000));
        assert!(
            l.events[scan as usize]
                .time_note
                .as_deref()
                .unwrap()
                .contains("heuristic")
        );
        assert_eq!(l.events[exp as usize].store, Some(0));
    }

    fn content(l: &mut Loaded, digests: Vec<(DigestAlg, u8)>) -> u32 {
        let e = ev(l, EventKind::FileHashed, Some(T), None);
        let id = l.contents.len() as u32;
        let len = |a| match a {
            DigestAlg::Md5 => 16,
            DigestAlg::Sha1 => 20,
            DigestAlg::Sha256 => 32,
        };
        l.contents.push(FileContent {
            id,
            fileref: FileRef {
                vsn: 1,
                record: id as u64,
                seq: 1,
            },
            digests: digests
                .into_iter()
                .map(|(a, b)| (a, vec![b; len(a)]))
                .collect(),
            event: e,
        });
        id
    }

    #[test]
    fn r4b_sha1_partial_conflicting_sha256_not_linked() {
        let mut l = Loaded::default();
        let a = content(&mut l, vec![(DigestAlg::Sha256, 1), (DigestAlg::Sha1, 2)]);
        let b = content(&mut l, vec![(DigestAlg::Sha1, 2)]);
        let c = content(&mut l, vec![(DigestAlg::Sha256, 9), (DigestAlg::Sha1, 2)]);
        let d = content(&mut l, vec![(DigestAlg::Sha256, 1)]);
        let e = content(&mut l, vec![(DigestAlg::Md5, 3)]);
        let f = content(&mut l, vec![(DigestAlg::Md5, 3)]);
        let (links, _) = link(&mut l, None);
        assert_eq!(
            has(&links, Node::Content(a), Node::Content(b), "4b"),
            Some(Strength::Partial)
        );
        assert_eq!(has(&links, Node::Content(a), Node::Content(c), "4b"), None);
        assert_eq!(
            has(&links, Node::Content(a), Node::Content(d), "4"),
            Some(Strength::Exact)
        );
        assert_eq!(
            has(&links, Node::Content(e), Node::Content(f), "4b"),
            Some(Strength::Heuristic)
        );
    }

    #[test]
    fn heuristic_volmap_caps_strength() {
        let mut l = Loaded::default();
        let a = loc(&mut l, r"C:\T\A.EXE", Strength::Heuristic);
        let e = ev(&mut l, EventKind::LowFiHit, Some(T), Some(a));
        let (links, _) = link(&mut l, None);
        assert_eq!(
            has(&links, Node::Location(a), Node::Event(e), "1"),
            Some(Strength::Heuristic)
        );
    }

    #[test]
    fn mft_rule3_requires_vsn() {
        let csv = b"EntryNumber,SequenceNumber,ParentPath,FileName\r\n7,1,.\\T,a.exe\r\n";
        let mut l = Loaded::default();
        let c = content(&mut l, vec![(DigestAlg::Sha256, 1)]);
        l.contents[c as usize].fileref = FileRef {
            vsn: 0xABCD,
            record: 7,
            seq: 1,
        };
        let other = load_mft_csv(csv, 0x1234, 'C').unwrap();
        let (links, _) = link(&mut l, Some(&other));
        assert!(links.iter().all(|k| k.rule != "3"));
        let mut l2 = l.clone();
        let idx = load_mft_csv(csv, 0xABCD, 'C').unwrap();
        let (links, _) = link(&mut l2, Some(&idx));
        let k = links.iter().find(|k| k.rule == "3").unwrap();
        assert_eq!(k.strength, Strength::Exact);
        let Node::Location(li) = (if matches!(k.a, Node::Location(_)) {
            k.a
        } else {
            k.b
        }) else {
            panic!()
        };
        assert_eq!(l2.locations[li as usize].key.0, r"C:\T\A.EXE");
    }

    #[test]
    fn r5_requires_pairwise_1ms_not_cluster() {
        let mut l = Loaded::default();
        let a = loc(&mut l, r"C:\A.EXE", Strength::Exact);
        let bpi = obs(&mut l, EventKind::ProcessFirstStart, Some(a), None, Some(T));
        obs(
            &mut l,
            EventKind::StoreProcessStart,
            Some(a),
            Some(5),
            Some(T + 7_500),
        );
        let far = obs(
            &mut l,
            EventKind::StoreProcessStart,
            Some(a),
            Some(5),
            Some(T + 15_000),
        );
        let (links, _) = link(&mut l, None);
        assert_eq!(has(&links, Node::Event(far), Node::Event(bpi), "5"), None);
        assert_eq!(
            has(&links, Node::Event(far), Node::Event(bpi), "5b"),
            Some(Strength::Partial)
        );
    }

    #[test]
    fn mft_link_capped_by_existing_heuristic_location() {
        let csv = b"EntryNumber,SequenceNumber,ParentPath,FileName\n7,1,.\\T,a.exe\n";
        let mut l = Loaded::default();
        loc(&mut l, r"C:\T\A.EXE", Strength::Heuristic);
        let c = content(&mut l, vec![(DigestAlg::Sha256, 1)]);
        l.contents[c as usize].fileref = FileRef {
            vsn: 5,
            record: 7,
            seq: 1,
        };
        let (links, _) = link(&mut l, Some(&load_mft_csv(csv, 5, 'C').unwrap()));
        assert_eq!(
            links.iter().find(|k| k.rule == "3").unwrap().strength,
            Strength::Heuristic
        );
    }

    #[test]
    fn mft_parent_whitespace_preserved_and_incomplete_rows_skipped() {
        let csv = b"EntryNumber,SequenceNumber,ParentPath,FileName\n7,1,\".\\T \",a.exe\n8,1\n";
        let idx = load_mft_csv(csv, 1, 'C').unwrap();
        assert_eq!(
            idx.by_ref.get(&(7, 1)).unwrap(),
            &vec![r"C:\T \a.exe".to_string()]
        );
        assert!(!idx.by_ref.contains_key(&(8, 1)));
        assert_eq!(idx.skipped, 1);
    }

    #[test]
    fn tact_queue_link_is_rule9() {
        let mut l = Loaded::default();
        obs(
            &mut l,
            EventKind::StoreProcessStart,
            None,
            Some(42),
            Some(T),
        );
        let q = obs(&mut l, EventKind::QueueEntry, None, Some(42), Some(T));
        let (links, runs) = link(&mut l, None);
        assert_eq!(
            has(&links, Node::Run(0), Node::Event(q), "9"),
            Some(Strength::Exact)
        );
        assert_eq!(runs.len(), 1);
    }

    #[test]
    fn threat_groups_only_named_columns() {
        let mut l = Loaded::default();
        let mk = |l: &mut Loaded, table: &str, col: &str| {
            let e = ev(l, EventKind::BmRecord, None, None);
            l.events[e as usize].prov = Prov::Db {
                table: table.into(),
                key: crate::model::RowKey::Rowid(e as i64),
                status: crate::model::DbStatus::InBoth,
                old: None,
            };
            l.events[e as usize].fields.push(Field {
                name: col.into(),
                display: "7".into(),
                raw: "7".into(),
            });
            e
        };
        let a = mk(&mut l, "BmFileActions", "ThreatRecordId");
        let b = mk(&mut l, "BmProcessInfo", "ThreatRecordId");
        let c = mk(&mut l, "BmFileStartupActions", "FdrThreatRecordId");
        let (links, _) = link(&mut l, None);
        assert_eq!(
            has(&links, Node::Event(a), Node::Event(c), "8"),
            Some(Strength::Partial)
        );
        assert!(
            links
                .iter()
                .all(|k| k.a != Node::Event(b) && k.b != Node::Event(b))
        );
    }

    #[test]
    fn mft_csv_quoted_fields() {
        let csv =
            b"FileName,ParentPath,SequenceNumber,EntryNumber\n\"a, b.txt\",\".\\Users\\x\",3,10\n";
        let idx = load_mft_csv(csv, 1, 'D').unwrap();
        assert_eq!(
            idx.by_ref.get(&(10, 3)).unwrap(),
            &vec![r"D:\Users\x\a, b.txt".to_string()]
        );
        assert!(load_mft_csv(b"Foo,Bar\n1,2\n", 1, 'C').is_err());
    }
}
