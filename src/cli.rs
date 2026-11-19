//! Headless command line (spec §9). Exit codes: 0 ok, 2 usage, 3 input unreadable, 4 decrypt failed,
//! 5 output refused (would overwrite an input or an existing file, or could not be written).
use crate::case::{Case, OpenError, OpenRequest, open};
use crate::correlate::load::LoadOpts;
use crate::decode::time::{Tz, parse_tz};
use crate::export::guard::{GuardError, OutputGuard};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

pub const USAGE: &str = "usage:
  mpdbx                          GUI
  mpdbx open <path>              GUI with a case preloaded
  mpdbx info <path>              evidence, WAL report and table counts
  mpdbx export <path> --out DIR [--format csv|json] [--force]
  mpdbx report <path> --out FILE.html [--bookmarks F.mpdbx.json] [--force]
  mpdbx diff <pathA> <pathB> --out FILE.csv|FILE.html [--force]
<path> = mpenginedb.db or a Scans folder (WAL and History are picked up next to it).
options: --key-dll mpengine.dll   --tz Z|+HH:MM   --volmap N=X (repeatable)
         --mft FILE --mft-vsn XXXX-XXXX --mft-drive X   (MFTECmd $MFT CSV bound to one volume)";

#[derive(Default, Debug)]
struct Args {
    cmd: String,
    pos: Vec<String>,
    out: Option<PathBuf>,
    format: Option<String>,
    force: bool,
    bookmarks: Option<PathBuf>,
    key_dll: Option<PathBuf>,
    mft: Option<PathBuf>,
    mft_vsn: Option<u32>,
    mft_drive: Option<char>,
    tz: Tz,
    volmap: Vec<(u32, char)>,
}

fn usage(msg: &str) -> ExitCode {
    eprintln!("mpdbx: {msg}\n\n{USAGE}");
    ExitCode::from(2)
}

fn parse_vsn(s: &str) -> Option<u32> {
    let h: String = s.chars().filter(|c| *c != '-').collect();
    (h.len() == 8)
        .then(|| u32::from_str_radix(&h, 16).ok())
        .flatten()
}

fn parse_drive(s: &str) -> Option<char> {
    let mut c = s.trim_end_matches(':').chars();
    match (c.next(), c.next()) {
        (Some(d), None) if d.is_ascii_alphabetic() => Some(d.to_ascii_uppercase()),
        _ => None,
    }
}

fn parse_args(argv: &[String]) -> Result<Args, String> {
    let mut a = Args {
        cmd: argv.get(1).cloned().unwrap_or_default(),
        ..Default::default()
    };
    let mut it = argv.iter().skip(2);
    while let Some(x) = it.next() {
        let mut val = |name: &str| it.next().cloned().ok_or(format!("{name} needs a value"));
        match x.as_str() {
            "--out" => a.out = Some(PathBuf::from(val("--out")?)),
            "--format" => a.format = Some(val("--format")?),
            "--force" => a.force = true,
            "--bookmarks" => a.bookmarks = Some(PathBuf::from(val("--bookmarks")?)),
            "--key-dll" => a.key_dll = Some(PathBuf::from(val("--key-dll")?)),
            "--mft" => a.mft = Some(PathBuf::from(val("--mft")?)),
            "--mft-vsn" => {
                let v = val("--mft-vsn")?;
                a.mft_vsn =
                    Some(parse_vsn(&v).ok_or(format!("--mft-vsn {v}: expected XXXX-XXXX"))?);
            }
            "--mft-drive" => {
                let v = val("--mft-drive")?;
                a.mft_drive = Some(
                    parse_drive(&v).ok_or(format!("--mft-drive {v}: expected a drive letter"))?,
                );
            }
            "--tz" => {
                let v = val("--tz")?;
                a.tz = parse_tz(&v).ok_or(format!("--tz {v}: expected Z or ±HH:MM"))?;
            }
            "--volmap" => {
                let v = val("--volmap")?;
                let (n, d) = v
                    .split_once('=')
                    .ok_or(format!("--volmap {v}: expected N=X"))?;
                a.volmap.push((
                    n.trim()
                        .parse()
                        .map_err(|_| format!("--volmap {v}: N must be a number"))?,
                    parse_drive(d).ok_or(format!("--volmap {v}: X must be a drive letter"))?,
                ));
            }
            o if o.starts_with("--") => return Err(format!("unknown option {o}")),
            p => a.pos.push(p.to_string()),
        }
    }
    if a.mft.is_some() != (a.mft_vsn.is_some() && a.mft_drive.is_some())
        || a.mft_vsn.is_some() != a.mft_drive.is_some()
    {
        return Err("--mft, --mft-vsn and --mft-drive go together".into());
    }
    Ok(a)
}

fn request(a: &Args, path: &str) -> OpenRequest {
    OpenRequest {
        path: PathBuf::from(path),
        key_dll: a.key_dll.clone(),
        mft: a
            .mft
            .clone()
            .zip(a.mft_vsn)
            .zip(a.mft_drive)
            .map(|((p, v), d)| (p, v, d)),
        opts: LoadOpts {
            tz: a.tz,
            volmap_assert: a.volmap.clone(),
        },
    }
}

fn open_case(a: &Args, path: &str) -> Result<Arc<Case>, ExitCode> {
    open(&request(a, path), &|_| {}).map_err(|e| {
        eprintln!("mpdbx: {path}: {e}");
        ExitCode::from(match e {
            OpenError::Unreadable(_) => 3,
            OpenError::WrongKey | OpenError::Pager(_) => 4,
        })
    })
}

fn refused(e: GuardError) -> ExitCode {
    eprintln!("mpdbx: {e}");
    ExitCode::from(5)
}

fn write_out(guard: &OutputGuard, path: &Path, force: bool, body: &[u8]) -> Result<(), ExitCode> {
    guard.check_file(path, force).map_err(refused)?;
    let mut f = crate::export::table::open_target(guard, path, force).map_err(refused)?;
    f.write_all(body)
        .map_err(|e| refused(GuardError::Io(e.to_string())))
}

fn info(c: &Case, path: &str) -> String {
    let e = &c.evidence;
    let w = &e.wal;
    let mut s = format!("mpdbx {} — {path}\nInputs:\n", env!("CARGO_PKG_VERSION"));
    for i in &e.inputs {
        s += &format!("  {}  {} bytes  SHA256 {}\n", i.path, i.size, i.sha256);
    }
    s += &format!(
        "Page size {}, pages {}, encrypted {}, key: {}\n",
        e.page_size, e.pages, e.encrypted, e.key_source
    );
    s += &format!(
        "WAL: present {}, header valid {}, frames total {}, validated {}, frames applied {}, commits {}, ignored after last commit {}, stop {}\n",
        w.present,
        w.header_valid,
        w.frames_total,
        w.frames_valid,
        w.frames_applied,
        w.commits,
        w.ignored_tail_frames,
        w.stop
            .as_ref()
            .map(|x| format!("{x:?}"))
            .unwrap_or_else(|| "none".into())
    );
    for (n, (d, st, sup)) in &e.volmap.map {
        s += &format!(
            "Volume map: HarddiskVolume{n} → {d}: ({st:?}; {})\n",
            sup.join(", ")
        );
    }
    s += "Tables (db-only / merged | DB, WAL-only, WAL-modified, removed by WAL, unknown):\n";
    for (n, a, b, st) in &e.table_counts {
        let o = |x: &Option<usize>| x.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
        s += &format!("  {n:<32} {:>6} / {:<6} | {:?}\n", o(a), o(b), st);
    }
    s += &format!(
        "Events {}  Locations {}  Process runs {}  Links {}\n",
        c.events.len(),
        c.locations.len(),
        c.runs.len(),
        c.links.len()
    );
    for x in &e.warnings {
        s += &format!("warning: {x}\n");
    }
    s
}

fn diff_html(rows: &[crate::export::diff::DiffRow]) -> String {
    use crate::export::report::esc;
    let body: String = rows
        .iter()
        .map(|r| {
            format!(
                "<tr><td>{}</td><td>{:?}</td><td class=\"m\">{}</td><td class=\"m\">{}</td><td class=\"m\">{}</td></tr>",
                esc(&r.view),
                r.change,
                esc(&r.key),
                esc(r.a.as_deref().unwrap_or("")),
                esc(r.b.as_deref().unwrap_or(""))
            )
        })
        .collect();
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>mpdbx diff</title><style>body{{font:13px 'Segoe UI',sans-serif;margin:16px}}\
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #ddd;padding:3px 6px;text-align:left;vertical-align:top}}\
.m{{font-family:Consolas,monospace;font-size:12px;word-break:break-all}}</style></head><body><h1>mpdbx diff</h1>\
<table><tr><th>View</th><th>Change</th><th>Key</th><th>A</th><th>B</th></tr>{body}</table></body></html>\n"
    )
}

pub fn run(argv: Vec<String>) -> ExitCode {
    let a = match parse_args(&argv) {
        Ok(a) => a,
        Err(e) => return usage(&e),
    };
    let need = |n: usize| a.pos.len() == n;
    let result: Result<(), ExitCode> = match a.cmd.as_str() {
        "info" if need(1) => open_case(&a, &a.pos[0]).and_then(|c| {
            let mut out = std::io::stdout();
            out.write_all(info(&c, &a.pos[0]).as_bytes())
                .and_then(|_| out.flush())
                .map_err(|e| refused(GuardError::Io(format!("writing to stdout: {e}"))))
        }),
        "export" if need(1) => {
            let Some(out) = a.out.clone() else {
                return usage("export needs --out DIR");
            };
            let json = match a.format.as_deref() {
                None | Some("csv") => false,
                Some("json") => true,
                Some(f) => return usage(&format!("--format {f}: use csv or json")),
            };
            open_case(&a, &a.pos[0]).and_then(|c| {
                let g = OutputGuard::new(&c.inputs.iter().collect::<Vec<_>>());
                let files = crate::export::table::export_all(&c, &out, json, &g, a.force)
                    .map_err(refused)?;
                println!("wrote {} files to {}", files.len(), out.display());
                Ok(())
            })
        }
        "report" if need(1) => {
            let Some(out) = a.out.clone() else {
                return usage("report needs --out FILE.html");
            };
            // one read: the bytes parsed are the bytes (and file identity) protected by the guard
            let (bm, bm_input) = match &a.bookmarks {
                Some(p) => match crate::evidence::read_input(p, 64 * 1024 * 1024)
                    .and_then(|i| crate::bookmarks::from_bytes(&i.bytes).map(|b| (b, i)))
                {
                    Ok((b, i)) => (b, Some(i)),
                    Err(e) => {
                        eprintln!("mpdbx: bookmarks {}: {e}", p.display());
                        return ExitCode::from(3);
                    }
                },
                None => (Default::default(), None),
            };
            open_case(&a, &a.pos[0]).and_then(|c| {
                // the bookmarks file is an input too: never an output target
                let mut inputs: Vec<&crate::evidence::Input> = c.inputs.iter().collect();
                inputs.extend(bm_input.iter());
                let g = OutputGuard::new(&inputs);
                write_out(
                    &g,
                    &out,
                    a.force,
                    crate::export::report::report(&c, &bm).as_bytes(),
                )?;
                println!("wrote {}", out.display());
                Ok(())
            })
        }
        "diff" if need(2) => {
            let Some(out) = a.out.clone() else {
                return usage("diff needs --out FILE.csv|FILE.html");
            };
            (|| {
                let ca = open_case(&a, &a.pos[0])?;
                let cb = open_case(&a, &a.pos[1])?;
                let rows = crate::export::diff::diff(&ca, &cb).map_err(|e| usage(&e))?;
                let mut inputs: Vec<&crate::evidence::Input> = ca.inputs.iter().collect();
                inputs.extend(cb.inputs.iter());
                let g = OutputGuard::new(&inputs);
                let html = out.extension().is_some_and(|x| {
                    x.eq_ignore_ascii_case("html") || x.eq_ignore_ascii_case("htm")
                });
                let body = if html {
                    diff_html(&rows).into_bytes()
                } else {
                    let mut v = Vec::new();
                    crate::export::diff::write_diff_csv(&rows, &mut v)
                        .map_err(|e| refused(GuardError::Io(e.to_string())))?;
                    v
                };
                write_out(&g, &out, a.force, &body)?;
                let n = |c| rows.iter().filter(|r| r.change == c).count();
                use crate::export::diff::Change::*;
                println!(
                    "{} added, {} removed, {} changed → {}",
                    n(Added),
                    n(Removed),
                    n(Changed),
                    out.display()
                );
                Ok(())
            })()
        }
        "info" | "export" | "report" | "diff" => {
            return usage(&format!("wrong number of paths for {}", a.cmd));
        }
        "" => return usage("no command"),
        c => return usage(&format!("unknown command {c}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => code,
    }
}

/// GUI-subsystem exe: attach to the parent console for CLI output unless stdout is already redirected.
pub fn attach_console() {
    use windows_sys::Win32::System::Console::{
        ATTACH_PARENT_PROCESS, AttachConsole, GetStdHandle, STD_OUTPUT_HANDLE,
    };
    // SAFETY: plain Win32 calls without pointers.
    unsafe {
        let h = GetStdHandle(STD_OUTPUT_HANDLE);
        if h.is_null() || h as isize == -1 {
            AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
}
