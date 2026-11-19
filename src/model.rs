//! Shared data model (spec §5).
use crate::normalize::path::PathKey;

/// FILETIME ticks (100 ns since 1601-01-01 UTC).
pub type Ft = u64;

/// Link strength; `Ord` makes `min()` the weakest.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum Strength {
    Heuristic,
    Partial,
    Exact,
}

/// Endpoint comparison of the DB-only and merged images (§5.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum DbStatus {
    InBoth,
    WalOnly,
    WalModified,
    RemovedByWal,
    Unknown,
}

#[derive(Clone, PartialEq, Debug)]
pub enum SqlVal {
    Null,
    Int(i64),
    Real(f64),
    Text(String),
    Blob(Vec<u8>),
}

#[derive(Clone, PartialEq, Debug)]
pub enum RowKey {
    Rowid(i64),
    Pk(Vec<SqlVal>),
    Full(Vec<SqlVal>),
}

#[derive(Clone, Debug)]
pub enum Prov {
    Db {
        table: String,
        key: RowKey,
        status: DbStatus,
        old: Option<Vec<SqlVal>>,
    },
    /// `section` 1 or 2; `offset` is relative to the start of the decrypted section.
    Store {
        file: String,
        section: u8,
        offset: u32,
    },
    Results {
        file: String,
        section: u8,
        offset: u32,
    },
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub display: String,
    pub raw: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum EventKind {
    ProcessFirstStart,
    ModuleFirstLoad,
    NoCertExec,
    OfnSet,
    OfnSetInferred,
    OfnProcessed,
    FileContext,
    LowFiHit,
    FileHashed,
    StoreProcessStart,
    FileScan,
    AmsiScan,
    AmsiProcessStart,
    StoreExpiry,
    RegistryChange,
    QueueEntry,
    RdpLogon,
    ScanRun,
    BmRecord,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub id: u32,
    pub kind: EventKind,
    pub time: Option<Ft>,
    pub time_note: Option<String>,
    pub summary: String,
    pub location: Option<u32>,
    pub obs: Option<u32>,
    pub content: Option<u32>,
    pub store: Option<u32>,
    pub fields: Vec<Field>,
    pub prov: Prov,
    pub flag: bool,
    /// How this event's own path spelling was resolved to its location (Heuristic through an inferred volume map).
    pub path_strength: Strength,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum LocClass {
    SystemDir,
    OutsideSystemDirs,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Location {
    pub id: u32,
    pub key: PathKey,
    pub spellings: Vec<String>,
    pub events: Vec<u32>,
    pub class: LocClass,
    pub key_strength: Strength,
}

#[derive(Clone, Debug)]
pub struct ProcessObs {
    pub id: u32,
    pub location: Option<u32>,
    pub pid: Option<u32>,
    pub start: Option<Ft>,
    pub event: u32,
    /// Path-resolution strength of the observation's location spelling (= its event's path_strength).
    pub path_strength: Strength,
}

#[derive(Clone, Debug)]
pub struct ProcessRun {
    pub id: u32,
    pub obs: Vec<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct FileRef {
    pub vsn: u32,
    pub record: u64,
    pub seq: u16,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum DigestAlg {
    Md5,
    Sha1,
    Sha256,
}

#[derive(Clone, Debug)]
pub struct FileContent {
    pub id: u32,
    pub fileref: FileRef,
    pub digests: Vec<(DigestAlg, Vec<u8>)>,
    pub event: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Node {
    Event(u32),
    Location(u32),
    Run(u32),
    Content(u32),
    Store(u32),
}

#[derive(Clone, Debug)]
pub struct Link {
    pub a: Node,
    pub b: Node,
    pub rule: &'static str,
    pub strength: Strength,
    pub note: String,
}

#[derive(Clone, Debug, Default)]
pub struct HostContext {
    pub facts: Vec<(String, String, Prov)>,
}

#[derive(Clone, Debug)]
pub struct RawTable {
    pub name: String,
    pub columns: Vec<String>,
    pub rows: Vec<(Vec<SqlVal>, Prov)>,
    pub readable: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strength_min_is_weakest() {
        assert_eq!(Strength::Exact.min(Strength::Partial), Strength::Partial);
        assert_eq!(
            Strength::Heuristic.min(Strength::Exact),
            Strength::Heuristic
        );
    }
    #[test]
    fn history_prov_carries_section() {
        let p = Prov::Results {
            file: "Quick/x".into(),
            section: 2,
            offset: 0x20,
        };
        assert!(matches!(
            p,
            Prov::Results {
                section: 2,
                offset: 0x20,
                ..
            }
        ));
    }
}
