//! Read-only evidence input (spec §4 Evidence safety).
use crate::model::Ft;
use sha2::Digest;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetFileInformationByHandle,
};

const ERROR_SHARING_VIOLATION: i32 = 32;
/// Hard ceiling for any single input (spec §4).
pub const MAX_INPUT: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Input {
    pub path: PathBuf,
    pub bytes: Vec<u8>,
    pub sha256: String,
    pub size: u64,
    pub mtime: Option<Ft>,
    pub changed_during_read: bool,
    pub shared_write_fallback: bool,
    /// (volume serial, file index)
    pub identity: Option<(u32, u64)>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct HandleInfo {
    vsn: u32,
    index: u64,
    size: u64,
    mtime: Ft,
}

fn handle_info(f: &File) -> Option<HandleInfo> {
    // SAFETY: zeroed POD out-parameter, valid handle owned by `f` for the duration of the call.
    let mut i: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    let ok = unsafe { GetFileInformationByHandle(f.as_raw_handle() as _, &mut i) };
    if ok == 0 {
        return None;
    }
    Some(HandleInfo {
        vsn: i.dwVolumeSerialNumber,
        index: ((i.nFileIndexHigh as u64) << 32) | i.nFileIndexLow as u64,
        size: ((i.nFileSizeHigh as u64) << 32) | i.nFileSizeLow as u64,
        mtime: ((i.ftLastWriteTime.dwHighDateTime as u64) << 32)
            | i.ftLastWriteTime.dwLowDateTime as u64,
    })
}

/// (volume serial, file index) of an open handle.
pub fn handle_identity(f: &File) -> Option<(u32, u64)> {
    handle_info(f).map(|h| (h.vsn, h.index))
}

/// (volume serial, file index) of an existing file or directory; opened with no access rights.
pub fn file_identity(path: &Path) -> Option<(u32, u64)> {
    let f = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .ok()?;
    handle_info(&f).map(|h| (h.vsn, h.index))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Reads a whole file read-only (share READ; falls back to READ|WRITE with a flag when another program
/// holds it open for writing), records SHA256, size, mtime, identity, and whether it changed during the read.
pub fn read_input(path: &Path, max: u64) -> Result<Input, String> {
    let max = max.min(MAX_INPUT);
    let open = |share| OpenOptions::new().read(true).share_mode(share).open(path);
    let (mut f, fallback) = match open(FILE_SHARE_READ) {
        Ok(f) => (f, false),
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => (
            open(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .map_err(|e| format!("{}: {e}", path.display()))?,
            true,
        ),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let before = handle_info(&f);
    let size_hint = before.map(|h| h.size).unwrap_or(0);
    if size_hint > max {
        return Err(format!(
            "{}: {size_hint} bytes exceeds the {max}-byte limit",
            path.display()
        ));
    }
    let mut bytes = Vec::with_capacity(size_hint as usize);
    (&mut f)
        .take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > max {
        return Err(format!(
            "{}: grew beyond the {max}-byte limit while reading",
            path.display()
        ));
    }
    let after = handle_info(&f);
    let changed = match (before, after) {
        (Some(b), Some(a)) => {
            b.size != a.size || b.mtime != a.mtime || a.size != bytes.len() as u64
        }
        _ => false,
    };
    Ok(Input {
        path: path.to_path_buf(),
        sha256: hex(&sha2::Sha256::digest(&bytes)),
        size: bytes.len() as u64,
        mtime: after.map(|h| h.mtime),
        changed_during_read: changed,
        shared_write_fallback: fallback,
        identity: after.map(|h| (h.vsn, h.index)),
        bytes,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("mpdbx_test_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn read_records_sha256_and_size() {
        let d = tmpdir("ev1");
        let p = d.join("a.bin");
        std::fs::write(&p, b"abc").unwrap();
        let i = read_input(&p, 1 << 20).unwrap();
        assert_eq!(
            i.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(i.size, 3);
        assert_eq!(i.bytes, b"abc");
        assert!(!i.changed_during_read);
        assert!(i.identity.is_some());
        assert!(i.mtime.is_some());
    }

    #[test]
    fn read_refuses_over_cap() {
        let d = tmpdir("ev2");
        let p = d.join("big.bin");
        std::fs::write(&p, vec![0u8; 100]).unwrap();
        assert!(read_input(&p, 10).is_err());
    }

    #[test]
    fn read_with_huge_max_is_clamped_not_overflowed() {
        let d = tmpdir("ev5");
        let p = d.join("a.bin");
        std::fs::write(&p, b"abc").unwrap();
        assert_eq!(read_input(&p, u64::MAX).unwrap().bytes, b"abc");
    }

    #[test]
    fn read_falls_back_when_file_open_for_writing() {
        let d = tmpdir("ev3");
        let p = d.join("w.bin");
        std::fs::write(&p, b"xyz").unwrap();
        let _w = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        let i = read_input(&p, 1 << 20).unwrap();
        assert!(i.shared_write_fallback);
        assert_eq!(i.bytes, b"xyz");
    }

    #[test]
    fn identity_same_for_hard_link() {
        let d = tmpdir("ev4");
        let p = d.join("x.bin");
        std::fs::write(&p, b"1").unwrap();
        std::fs::hard_link(&p, d.join("y.bin")).unwrap();
        assert_eq!(file_identity(&p), file_identity(&d.join("y.bin")));
        assert!(file_identity(&d.join("missing")).is_none());
    }
}
