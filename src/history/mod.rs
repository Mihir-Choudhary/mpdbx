//! Scans\History\Store and Results records (spec §3).
pub mod container;
pub mod results;
pub mod store;

use crate::crypto::Key;
use crate::evidence::Input;
use std::path::Path;

pub use container::ParseErr;
pub use results::ScanRec;
pub use store::{PropVal, StoreKind, StoreRec};

#[derive(Clone, Debug, Default)]
pub struct HistoryLoad {
    pub store: Vec<StoreRec>,
    pub scans: Vec<ScanRec>,
    pub errors: Vec<ParseErr>,
    pub inputs: Vec<Input>,
}

/// `history_dir` = `…\Scans\History` (containing `Store` and `Results`); missing parts are skipped.
pub fn load_history(history_dir: &Path, key: &Key) -> HistoryLoad {
    let (store, mut errors, mut inputs) = store::load_store(&history_dir.join("Store"), key);
    let (scans, e2, i2) = results::load_results(&history_dir.join("Results"), key);
    errors.extend(e2);
    inputs.extend(i2);
    HistoryLoad {
        store,
        scans,
        errors,
        inputs,
    }
}
