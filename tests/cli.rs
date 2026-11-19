//! Runs the built binary (spec §9).
use std::path::{Path, PathBuf};
use std::process::Command;

fn exe() -> Command {
    Command::new(env!("CARGO_BIN_EXE_mpdbx"))
}

fn fx(v: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(v)
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("mpdbx_cli_{tag}_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str]) -> (i32, String, String) {
    let o = exe().args(args).output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn s(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[test]
fn cli_info_fixture_exit0() {
    let (code, out, err) = run(&["info", s(&fx("multi_commit"))]);
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("frames applied")
            && out.contains("BackupProcessInfo")
            && out.contains("SHA256"),
        "{out}"
    );
}

#[test]
fn cli_usage_exit2() {
    assert_eq!(run(&["frobnicate"]).0, 2);
    assert_eq!(
        run(&["export", s(&fx("multi_commit"))]).0,
        2,
        "export needs --out"
    );
    assert_eq!(run(&["info", s(&fx("multi_commit")), "--tz", "bogus"]).0, 2);
    assert_eq!(
        run(&["info", s(&fx("multi_commit")), "--mft", "x.csv"]).0,
        2,
        "--mft needs --mft-vsn and --mft-drive"
    );
    assert_eq!(
        run(&["info", s(&fx("multi_commit")), "--volmap", "three=C"]).0,
        2
    );
}

#[test]
fn cli_missing_input_exit3() {
    assert_eq!(run(&["info", s(&tmp("missing").join("nope"))]).0, 3);
}

#[test]
fn cli_wrong_key_exit4() {
    let d = tmp("wrongkey");
    let mut db = std::fs::read(fx("nowal").join("mpenginedb.db")).unwrap();
    db[0] ^= 0xFF;
    std::fs::write(d.join("mpenginedb.db"), db).unwrap();
    assert_eq!(run(&["info", s(&d)]).0, 4);
}

#[test]
fn cli_export_onto_input_exit_5() {
    let d = tmp("onto_input");
    for f in ["mpenginedb.db", "mpenginedb.db-wal"] {
        std::fs::copy(fx("multi_commit").join(f), d.join(f)).unwrap();
    }
    let before = std::fs::read(d.join("mpenginedb.db")).unwrap();
    let (code, _, err) = run(&[
        "report",
        s(&d),
        "--out",
        s(&d.join("mpenginedb.db")),
        "--force",
    ]);
    assert_eq!(code, 5, "{err}");
    assert_eq!(std::fs::read(d.join("mpenginedb.db")).unwrap(), before);
    std::fs::write(d.join("r.html"), b"old").unwrap();
    assert_eq!(
        run(&["report", s(&d), "--out", s(&d.join("r.html"))]).0,
        5,
        "existing file without --force"
    );
}

#[test]
fn cli_report_never_overwrites_its_bookmarks_input() {
    let d = tmp("bm_input");
    std::fs::write(d.join("b.mpdbx.json"), br#"{"items":[]}"#).unwrap();
    let (code, _, err) = run(&[
        "report",
        s(&fx("multi_commit")),
        "--bookmarks",
        s(&d.join("b.mpdbx.json")),
        "--out",
        s(&d.join("b.mpdbx.json")),
        "--force",
    ]);
    assert_eq!(code, 5, "{err}");
    assert_eq!(
        std::fs::read(d.join("b.mpdbx.json")).unwrap(),
        br#"{"items":[]}"#
    );
}

#[test]
fn cli_export_writes_views_and_report() {
    let d = tmp("export");
    let (code, out, err) = run(&["export", s(&fx("multi_commit")), "--out", s(&d.join("csv"))]);
    assert_eq!(code, 0, "{err}");
    assert!(d.join("csv").join("Timeline.csv").is_file(), "{out}");
    let (code, _, err) = run(&[
        "export",
        s(&fx("multi_commit")),
        "--out",
        s(&d.join("json")),
        "--format",
        "json",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(d.join("json").join("Timeline.json").is_file());
    let (code, _, err) = run(&[
        "report",
        s(&fx("multi_commit")),
        "--out",
        s(&d.join("r.html")),
        "--tz",
        "+05:30",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        std::fs::read_to_string(d.join("r.html"))
            .unwrap()
            .contains("+05:30")
    );
}

#[test]
fn cli_diff_two_fixtures() {
    let d = tmp("diff");
    let (code, out, err) = run(&[
        "diff",
        s(&fx("uncommitted_tail")),
        s(&fx("multi_commit")),
        "--out",
        s(&d.join("d.csv")),
    ]);
    assert_eq!(code, 0, "{err}");
    let csv = std::fs::read_to_string(d.join("d.csv")).unwrap();
    assert!(csv.contains("Added") && csv.contains("FileHashed"), "{csv}");
    assert!(out.contains("added"), "{out}");
    let (code, _, err) = run(&[
        "diff",
        s(&fx("uncommitted_tail")),
        s(&fx("multi_commit")),
        "--out",
        s(&d.join("d.html")),
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(
        std::fs::read_to_string(d.join("d.html"))
            .unwrap()
            .starts_with("<!doctype html>")
    );
}

#[test]
fn cli_non_unicode_argument_does_not_panic() {
    use std::os::windows::ffi::OsStringExt;
    let mut w: Vec<u16> = r"C:\evidence\".encode_utf16().collect();
    w.push(0xD800);
    w.extend(r"\mpenginedb.db".encode_utf16());
    let bad = std::ffi::OsString::from_wide(&w);
    let o = exe().arg("info").arg(bad).output().unwrap();
    let code = o.status.code().unwrap_or(-1);
    assert!(
        code == 2 || code == 3,
        "exit {code}, stderr {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// review #9: help and version are not usage errors.
#[test]
fn help_and_version_exit_zero() {
    for a in ["--help", "-h", "--version"] {
        let o = std::process::Command::new(env!("CARGO_BIN_EXE_mpdbx"))
            .arg(a)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(0), "{a}");
        assert!(!o.stdout.is_empty(), "{a} prints something");
    }
}
