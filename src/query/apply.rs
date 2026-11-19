//! Filtering, facet counts and histogram over a `Case` (spec §7, §8.2).
use super::parse::Term;
use crate::case::Case;
use crate::model::{DbStatus, Event, EventKind, Ft, LocClass, Node, Prov, Strength};
use std::collections::{BTreeMap, HashSet};

/// Timed / untimed selection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TimeSel {
    #[default]
    All,
    Timed,
    Untimed,
}

/// `None` = no restriction; `Some(set)` = only these values (an empty set selects nothing).
/// `status` uses `None` for Store/Results events (not database rows); `strength` uses `None` for unlinked events.
#[derive(Clone, Debug, Default)]
pub struct FacetSel {
    pub kinds: Option<HashSet<EventKind>>,
    pub loc: Option<HashSet<LocClass>>,
    pub status: Option<HashSet<Option<DbStatus>>>,
    pub strength: Option<HashSet<Option<Strength>>>,
    pub tables: Option<HashSet<String>>,
    pub time: TimeSel,
    /// Only events at a location that has a no-embedded-cert execution (same predicate as `nocert:yes`).
    pub nocert_only: bool,
    /// Only red-flag events (§10 red-flag rules).
    pub flagged_only: bool,
    /// Exact location (Location id) — set by the inspector's "Same location" pivot.
    pub location: Option<u32>,
    /// Exact process run (ProcessRun id) — events whose observation belongs to the run.
    pub run: Option<u32>,
    /// Exact event set (a Findings card): the list shows precisely the events the card counted.
    pub only: Option<std::sync::Arc<HashSet<u32>>>,
}

#[derive(Clone, Debug, Default)]
pub struct Query {
    pub terms: Vec<(bool, Term)>,
    /// Inclusive UTC window (brushed in the histogram).
    pub window: Option<(Ft, Ft)>,
    pub facets: FacetSel,
}

#[derive(Clone, Debug, Default)]
pub struct FacetCounts {
    pub kinds: Vec<(EventKind, usize)>,
    pub loc: Vec<(LocClass, usize)>,
    pub status: Vec<(Option<DbStatus>, usize)>,
    pub strength: Vec<(Option<Strength>, usize)>,
    pub tables: Vec<(String, usize)>,
    pub timed: usize,
    pub no_time: usize,
    pub nocert: usize,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Histogram {
    pub start: Ft,
    pub width: Ft,
    pub counts: Vec<u32>,
}

/// Lower-case search text per event: summary, field displays, location key and spellings.
pub fn build_index(case: &Case) -> Vec<String> {
    case.events
        .iter()
        .map(|e| {
            let mut s = e.summary.to_lowercase();
            for f in &e.fields {
                s.push('\u{1}');
                s.push_str(&f.display.to_lowercase());
            }
            if let Some(l) = e.location.and_then(|l| case.locations.get(l as usize)) {
                s.push('\u{1}');
                // key only: copying every spelling into every event multiplies (spellings × events); `path:` checks spellings
                s.push_str(&l.key.0.to_lowercase());
            }
            s
        })
        .collect()
}

pub fn source_table(e: &Event) -> String {
    match &e.prov {
        Prov::Db { table, .. } => table.clone(),
        Prov::Store { .. } => "Store".into(),
        Prov::Results { .. } => "Results".into(),
    }
}

fn status(e: &Event) -> Option<DbStatus> {
    match &e.prov {
        Prov::Db { status, .. } => Some(*status),
        _ => None,
    }
}

fn loc_class(case: &Case, e: &Event) -> LocClass {
    e.location
        .and_then(|l| case.locations.get(l as usize))
        .map(|l| l.class)
        .unwrap_or(LocClass::Unknown)
}

/// Strongest link touching the event (None when unlinked).
pub fn best_strength(case: &Case, id: u32) -> Option<Strength> {
    case.links_by_node
        .get(&Node::Event(id))?
        .iter()
        .map(|&i| case.links[i as usize].strength)
        .max()
}

/// Lower-case event-type names (what `type:` matches against).
pub fn kind_lc(k: EventKind) -> &'static str {
    use EventKind::*;
    match k {
        ProcessFirstStart => "processfirststart",
        ModuleFirstLoad => "modulefirstload",
        NoCertExec => "nocertexec",
        OfnSet => "ofnset",
        OfnSetInferred => "ofnsetinferred",
        OfnProcessed => "ofnprocessed",
        FileContext => "filecontext",
        LowFiHit => "lowfihit",
        FileHashed => "filehashed",
        StoreProcessStart => "storeprocessstart",
        FileScan => "filescan",
        AmsiScan => "amsiscan",
        AmsiProcessStart => "amsiprocessstart",
        StoreExpiry => "storeexpiry",
        RegistryChange => "registrychange",
        QueueEntry => "queueentry",
        RdpLogon => "rdplogon",
        ScanRun => "scanrun",
        BmRecord => "bmrecord",
    }
}

/// Per-query precomputation shared by every event.
struct Ctx {
    /// Events of the selected process run (FacetSel::run).
    run_events: Option<HashSet<u32>>,
    /// Locations with at least one no-embedded-cert execution.
    nocert: HashSet<u32>,
}

fn nocert_locations(case: &Case) -> HashSet<u32> {
    case.events
        .iter()
        .filter(|e| e.kind == EventKind::NoCertExec)
        .filter_map(|e| e.location)
        .collect()
}

fn term_matches(case: &Case, ctx: &Ctx, idx: &str, e: &Event, t: &Term) -> bool {
    let loc = e.location.and_then(|l| case.locations.get(l as usize));
    match t {
        Term::Text(s) => idx.contains(s.as_str()),
        Term::Path(g) => {
            loc.is_some_and(|l| g.matches(&l.key.0) || l.spellings.iter().any(|s| g.matches(s)))
        }
        Term::Name(g) => loc.is_some_and(|l| g.matches(l.key.0.rsplit('\\').next().unwrap_or(""))),
        // Only validated digests of the requested algorithm (FileHashes content), never other fields.
        Term::Digest(alg, g) => e
            .content
            .and_then(|c| case.contents.get(c as usize))
            .is_some_and(|c| {
                c.digests
                    .iter()
                    .any(|(a, d)| a == alg && g.matches_lower(&crate::decode::values::hex(d)))
            }),
        Term::Pid(p) => e
            .obs
            .and_then(|o| case.obs.get(o as usize))
            .is_some_and(|o| o.pid == Some(*p)),
        Term::Type(g) => g.matches_lower(kind_lc(e.kind)),
        Term::Src(st) => status(e) == Some(*st),
        Term::Loc(c) => loc_class(case, e) == *c,
        Term::NoCert => e.location.is_some_and(|l| ctx.nocert.contains(&l)),
        Term::After(t) => e.time.is_some_and(|x| x >= *t),
        Term::Before(t) => e.time.is_some_and(|x| x <= *t),
        Term::Regex(r) => r.is_match(idx),
    }
}

fn allows<T: Eq + std::hash::Hash>(sel: &Option<HashSet<T>>, v: &T) -> bool {
    sel.as_ref().is_none_or(|s| s.contains(v))
}

fn facet_ok(case: &Case, ctx: &Ctx, e: &Event, f: &FacetSel) -> bool {
    f.only.as_ref().is_none_or(|s| s.contains(&e.id))
        && allows(&f.kinds, &e.kind)
        && allows(&f.loc, &loc_class(case, e))
        && allows(&f.status, &status(e))
        && allows(&f.strength, &best_strength(case, e.id))
        && allows(&f.tables, &source_table(e))
        && match f.time {
            TimeSel::All => true,
            TimeSel::Timed => e.time.is_some(),
            TimeSel::Untimed => e.time.is_none(),
        }
        && !(f.nocert_only && !e.location.is_some_and(|l| ctx.nocert.contains(&l)))
        && !(f.flagged_only && !e.flag)
        && f.location.is_none_or(|l| e.location == Some(l))
        && ctx.run_events.as_ref().is_none_or(|s| s.contains(&e.id))
}

/// Event ids matching every term, the window and the facets; time-sorted, no-time events last.
pub fn apply(case: &Case, idx: &[String], q: &Query) -> Vec<u32> {
    let run_events = q.facets.run.and_then(|r| case.runs.get(r as usize)).map(|r| r.obs.iter().filter_map(|&o| case.obs.get(o as usize)).map(|o| o.event).collect());
    let ctx = Ctx { nocert: nocert_locations(case), run_events };
    let mut ids: Vec<u32> = case
        .events
        .iter()
        .filter(|e| {
            let text = idx.get(e.id as usize).map(String::as_str).unwrap_or("");
            q.terms
                .iter()
                .all(|(neg, t)| term_matches(case, &ctx, text, e, t) != *neg)
                && q.window
                    .is_none_or(|(a, b)| e.time.is_some_and(|t| t >= a && t <= b))
                && facet_ok(case, &ctx, e, &q.facets)
        })
        .map(|e| e.id)
        .collect();
    ids.sort_by_key(|&i| {
        let e = &case.events[i as usize];
        (e.time.is_none(), e.time.unwrap_or(0), i)
    });
    ids
}

fn count<K: Ord + Clone>(it: impl Iterator<Item = K>) -> Vec<(K, usize)> {
    let mut m: BTreeMap<K, usize> = BTreeMap::new();
    for k in it {
        *m.entry(k).or_default() += 1;
    }
    m.into_iter().collect()
}

pub fn facet_counts(case: &Case, ids: &[u32]) -> FacetCounts {
    let nocert_locs = nocert_locations(case);
    let evs = || ids.iter().filter_map(|&i| case.events.get(i as usize));
    let kinds = {
        let mut m: Vec<(EventKind, usize)> = Vec::new();
        for e in evs() {
            match m.iter_mut().find(|x| x.0 == e.kind) {
                Some(x) => x.1 += 1,
                None => m.push((e.kind, 1)),
            }
        }
        m
    };
    let order = |c: LocClass| c as u8;
    let mut loc: Vec<(LocClass, usize)> = Vec::new();
    for e in evs() {
        let c = loc_class(case, e);
        match loc.iter_mut().find(|x| x.0 == c) {
            Some(x) => x.1 += 1,
            None => loc.push((c, 1)),
        }
    }
    loc.sort_by_key(|x| order(x.0));
    let mut status_v: Vec<(Option<DbStatus>, usize)> = Vec::new();
    for s in evs().map(status) {
        match status_v.iter_mut().find(|x| x.0 == s) {
            Some(x) => x.1 += 1,
            None => status_v.push((s, 1)),
        }
    }
    FacetCounts {
        kinds,
        loc,
        status: status_v,
        strength: count(evs().map(|e| best_strength(case, e.id))),
        tables: count(evs().map(source_table)),
        timed: evs().filter(|e| e.time.is_some()).count(),
        no_time: evs().filter(|e| e.time.is_none()).count(),
        nocert: evs()
            .filter(|e| e.location.is_some_and(|l| nocert_locs.contains(&l)))
            .count(),
    }
}

/// Live facet counts: each group's counts apply every other active facet, but not the group's own selection
/// (so a group always shows what selecting a value would give).
pub fn facet_counts_q(case: &Case, idx: &[String], q: &Query) -> FacetCounts {
    let with = |clear: &dyn Fn(&mut FacetSel)| {
        let mut qq = q.clone();
        clear(&mut qq.facets);
        facet_counts(case, &apply(case, idx, &qq))
    };
    FacetCounts {
        kinds: with(&|f| f.kinds = None).kinds,
        loc: with(&|f| f.loc = None).loc,
        status: with(&|f| f.status = None).status,
        strength: with(&|f| f.strength = None).strength,
        tables: with(&|f| f.tables = None).tables,
        timed: with(&|f| f.time = TimeSel::All).timed,
        no_time: with(&|f| f.time = TimeSel::All).no_time,
        nocert: with(&|f| f.nocert_only = false).nocert,
    }
}

const MINUTE: Ft = 600_000_000;
const HOUR: Ft = 60 * MINUTE;
const DAY: Ft = 24 * HOUR;

/// Bucket width by span (minute < 6 h, hour < 14 d, else day), widened to whole multiples if more than
/// `max_buckets` would be needed. `start` is aligned to the width.
pub fn histogram(case: &Case, ids: &[u32], max_buckets: usize) -> Histogram {
    let times: Vec<Ft> = ids
        .iter()
        .filter_map(|&i| case.events.get(i as usize)?.time)
        .collect();
    let (Some(&lo), Some(&hi)) = (times.iter().min(), times.iter().max()) else {
        return Histogram::default();
    };
    let span = hi - lo;
    let mut width = if span < 6 * HOUR {
        MINUTE
    } else if span < 14 * DAY {
        HOUR
    } else {
        DAY
    };
    let max_buckets = max_buckets.max(1) as Ft;
    let base = width;
    while (hi / width - lo / width + 1) > max_buckets {
        width += base;
    }
    let start = lo / width * width;
    let n = ((hi - start) / width + 1) as usize;
    let mut counts = vec![0u32; n];
    for t in times {
        counts[((t - start) / width) as usize] += 1;
    }
    Histogram {
        start,
        width,
        counts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::case::{Case, OpenRequest, open};
    use crate::decode::time::Tz;
    use crate::model::EventKind;
    use std::sync::Arc;

    fn case() -> Arc<Case> {
        let p =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/multi_commit");
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

    fn q(s: &str) -> Query {
        Query {
            terms: crate::query::parse(s, Tz::default()).unwrap(),
            ..Default::default()
        }
    }

    #[test]
    fn apply_text_and_terms() {
        let c = case();
        let idx = build_index(&c);
        let all = apply(&c, &idx, &Query::default());
        assert_eq!(all.len(), c.events.len());
        let nc = apply(&c, &idx, &q("nocert:yes type:nocert"));
        assert_eq!(nc.len(), 2);
        assert!(
            apply(&c, &idx, &q("b.exe"))
                .iter()
                .all(|&i| idx[i as usize].contains("b.exe"))
        );
        let not_module = apply(&c, &idx, &q("-type:module"));
        assert!(
            not_module
                .iter()
                .all(|&i| c.events[i as usize].kind != EventKind::ModuleFirstLoad)
        );
        assert_eq!(
            apply(&c, &idx, &q("pid:4120")).len(),
            2,
            "Store process start + Tact queue entry"
        );
        assert_eq!(
            apply(&c, &idx, &q(&format!("sha256:{}", "33".repeat(32)))).len(),
            1
        );
    }

    #[test]
    fn digest_matches_only_requested_algorithm() {
        let c = case();
        let idx = build_index(&c);
        assert_eq!(
            apply(&c, &idx, &q(&format!("sha256:{}", "11".repeat(16)))).len(),
            0,
            "MD5 value must not match sha256:"
        );
        assert_eq!(
            apply(&c, &idx, &q(&format!("md5:{}", "11".repeat(16)))).len(),
            1
        );
    }

    #[test]
    fn globs_in_type_and_digest_values() {
        let c = case();
        let idx = build_index(&c);
        let m = apply(&c, &idx, &q("type:Module*"));
        assert!(
            !m.is_empty()
                && m.iter()
                    .all(|&i| c.events[i as usize].kind == EventKind::ModuleFirstLoad)
        );
        assert_eq!(apply(&c, &idx, &q("sha256:33*")).len(), 1);
        assert_eq!(
            apply(&c, &idx, &q("sha256:3333")).len(),
            1,
            "no wildcard = prefix"
        );
    }

    #[test]
    fn regex_keeps_spaces_and_quotes() {
        let t = crate::query::parse(r#"/foo bar/ /"q"/"#, Tz::default()).unwrap();
        assert_eq!(t.len(), 2);
        assert!(matches!(&t[0].1, crate::query::Term::Regex(r) if r.is_match("xx foo bar")));
        assert!(
            matches!(&t[1].1, crate::query::Term::Regex(r) if r.is_match("\"q\"") && !r.is_match("q"))
        );
    }

    #[test]
    fn nocert_facet_selects_and_counts() {
        let c = case();
        let idx = build_index(&c);
        let mut f = Query::default();
        f.facets.nocert_only = true;
        let ids = apply(&c, &idx, &f);
        assert_eq!(ids.len(), apply(&c, &idx, &q("nocert:yes")).len());
        assert_eq!(facet_counts(&c, &all_ids(&c)).nocert, ids.len());
    }

    #[test]
    fn nocert_filter_is_not_quadratic() {
        let base = case();
        let mut c = (*base).clone();
        let loc = c
            .locations
            .iter()
            .position(|l| l.key.0.ends_with(r"\M.DLL"))
            .unwrap() as u32;
        let tmpl = c.events[c.locations[loc as usize].events[0] as usize].clone();
        for _ in 0..20_000 {
            let mut e = tmpl.clone();
            e.id = c.events.len() as u32;
            c.locations[loc as usize].events.push(e.id);
            c.events.push(e);
        }
        let idx = build_index(&c);
        let t = std::time::Instant::now();
        apply(&c, &idx, &q("nocert:yes"));
        assert!(t.elapsed().as_millis() < 1000, "{:?}", t.elapsed());
    }

    #[test]
    fn explicit_empty_selection_shows_nothing() {
        let c = case();
        let mut q = Query::default();
        q.facets.kinds = Some(HashSet::new());
        assert!(apply(&c, &build_index(&c), &q).is_empty());
    }

    #[test]
    fn history_rows_survive_db_status_restriction() {
        let c = case();
        let mut q = Query::default();
        q.facets.status = Some(
            [
                Some(DbStatus::InBoth),
                Some(DbStatus::WalOnly),
                Some(DbStatus::WalModified),
                Some(DbStatus::RemovedByWal),
                None,
            ]
            .into(),
        );
        let ids = apply(&c, &build_index(&c), &q);
        assert!(
            ids.iter()
                .any(|&i| matches!(c.events[i as usize].prov, crate::model::Prov::Store { .. }))
        );
        q.facets.status = Some([Some(DbStatus::InBoth)].into());
        let ids = apply(&c, &build_index(&c), &q);
        assert!(ids.iter().all(|&i| matches!(
            c.events[i as usize].prov,
            crate::model::Prov::Db {
                status: DbStatus::InBoth,
                ..
            }
        )));
    }

    #[test]
    fn untimed_only_selection() {
        let c = case();
        let mut q = Query::default();
        q.facets.time = TimeSel::Untimed;
        let ids = apply(&c, &build_index(&c), &q);
        assert!(!ids.is_empty() && ids.iter().all(|&i| c.events[i as usize].time.is_none()));
    }

    #[test]
    fn counts_respect_other_groups() {
        let c = case();
        let mut q = Query::default();
        q.facets.loc = Some([LocClass::OutsideSystemDirs].into());
        let counts = facet_counts_q(&c, &build_index(&c), &q);
        assert_eq!(
            counts
                .kinds
                .iter()
                .find(|k| k.0 == EventKind::ModuleFirstLoad)
                .map(|k| k.1)
                .unwrap_or(0),
            0,
            "module lives in a system dir"
        );
        assert!(
            counts
                .loc
                .iter()
                .any(|x| x.0 == LocClass::SystemDir && x.1 > 0),
            "own group ignores its own selection"
        );
    }

    #[test]
    fn location_and_run_facets_are_exact() {
        let c = case();
        let idx = build_index(&c);
        let e = c.events.iter().find(|e| e.kind == EventKind::NoCertExec).unwrap();
        let mut q = Query::default();
        q.facets.location = e.location;
        let ids = apply(&c, &idx, &q);
        assert!(ids.len() >= 2 && ids.iter().all(|&i| c.events[i as usize].location == e.location));
        let run = c.runs.iter().position(|r| r.obs.len() >= 2).unwrap() as u32;
        let mut q = Query::default();
        q.facets.run = Some(run);
        let ids = apply(&c, &idx, &q);
        let members: Vec<u32> = c.runs[run as usize].obs.iter().map(|&o| c.obs[o as usize].event).collect();
        assert_eq!(ids.len(), members.len());
        assert!(ids.iter().all(|i| members.contains(i)));
    }

    #[test]
    fn flagged_only_facet() {
        let c = case();
        let idx = build_index(&c);
        let mut q = Query::default();
        q.facets.flagged_only = true;
        let ids = apply(&c, &idx, &q);
        assert!(!ids.is_empty() && ids.iter().all(|&i| c.events[i as usize].flag));
    }

    #[test]
    fn apply_window_and_facets() {
        let c = case();
        let idx = build_index(&c);
        let t0 = 134369015368153546u64;
        let w = Query {
            window: Some((t0, t0 + 10)),
            ..Default::default()
        };
        let ids = apply(&c, &idx, &w);
        assert!(!ids.is_empty());
        assert!(ids.iter().all(|&i| {
            c.events[i as usize]
                .time
                .is_some_and(|t| t >= t0 && t <= t0 + 10)
        }));
        let mut f = Query::default();
        f.facets.kinds = Some([EventKind::LowFiHit].into());
        assert_eq!(apply(&c, &idx, &f).len(), 1);
        let mut h = Query::default();
        h.facets.time = TimeSel::Timed;
        assert!(
            apply(&c, &idx, &h)
                .iter()
                .all(|&i| c.events[i as usize].time.is_some())
        );
        let counts = facet_counts(&c, &all_ids(&c));
        assert_eq!(
            counts
                .kinds
                .iter()
                .find(|k| k.0 == EventKind::NoCertExec)
                .map(|k| k.1),
            Some(2)
        );
        assert!(counts.no_time >= 1);
    }

    fn all_ids(c: &Case) -> Vec<u32> {
        (0..c.events.len() as u32).collect()
    }

    #[test]
    fn no_time_events_last_and_sorted() {
        let c = case();
        let ids = apply(&c, &build_index(&c), &Query::default());
        let times: Vec<Option<u64>> = ids.iter().map(|&i| c.events[i as usize].time).collect();
        let first_none = times
            .iter()
            .position(|t| t.is_none())
            .unwrap_or(times.len());
        assert!(times[first_none..].iter().all(|t| t.is_none()));
        assert!(times[..first_none].windows(2).all(|w| w[0] <= w[1]));
    }

    #[test]
    fn histogram_buckets_follow_span_and_cap() {
        let c = case();
        let span = {
            let t: Vec<u64> = c.events.iter().filter_map(|e| e.time).collect();
            t.iter().max().unwrap() - t.iter().min().unwrap()
        };
        assert!(span < 6 * 36_000_000_000, "fixture spans about an hour");
        let h = histogram(&c, &all_ids(&c), 200);
        assert_eq!(h.width, 600_000_000, "span < 6 h → minute buckets");
        let timed = c.events.iter().filter(|e| e.time.is_some()).count() as u32;
        assert_eq!(h.counts.iter().sum::<u32>(), timed);
        assert_eq!(h.start % h.width, 0);
        let capped = histogram(&c, &all_ids(&c), 10);
        assert!(capped.counts.len() <= 10 && capped.width % 600_000_000 == 0);
        assert_eq!(capped.counts.iter().sum::<u32>(), timed);
    }

    #[test]
    #[ignore]
    fn apply_100k_under_50ms() {
        let base = case();
        let mut c = (*base).clone();
        let n0 = c.events.len();
        while c.events.len() < 100_000 {
            let mut e = c.events[c.events.len() % n0].clone();
            e.id = c.events.len() as u32;
            e.time = e.time.map(|t| t + e.id as u64 * 10_000_000);
            c.events.push(e);
        }
        let idx = build_index(&c);
        let query = q(r"path:c:\t\* -type:module after:2026-10-19");
        let t = std::time::Instant::now();
        let ids = apply(&c, &idx, &query);
        let el = t.elapsed();
        eprintln!("{} of {} in {el:?}", ids.len(), c.events.len());
        assert!(el.as_millis() < 50, "{el:?}");
    }
}
