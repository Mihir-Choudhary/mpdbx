//! Windows path parsing and identity keys (spec §5.1).
use crate::model::{LocClass, Strength};
use crate::normalize::volmap::VolMap;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathKey(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PathKind {
    Drive(char),
    Device(u32),
    Unc,
    VolumeGuid,
    SystemRoot,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WinPath {
    pub kind: PathKind,
    /// Components after the root (for Unc: server, share, …; for VolumeGuid: `Volume{…}`, …).
    pub components: Vec<String>,
    /// `ENG:<TAG>` prefix split off before parsing.
    pub tag: Option<String>,
    pub raw: String,
}

fn strip_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &s[prefix.len()..])
}

fn split_tag(s: &str) -> (Option<String>, &str) {
    if let Some(rest) = s.strip_prefix("ENG:")
        && let Some((tag, path)) = rest.split_once(':')
        && !tag.is_empty()
        && tag
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
    {
        return (Some(format!("ENG:{tag}")), path);
    }
    (None, s)
}

/// Components verbatim (no `.`/`..` resolution, internal empty components kept); only the root separator
/// and a single trailing separator are dropped.
fn components(rest: &str) -> Vec<String> {
    let r = rest.strip_prefix('\\').unwrap_or(rest);
    if r.is_empty() {
        return Vec::new();
    }
    let mut v: Vec<String> = r.split('\\').map(str::to_string).collect();
    if v.last().is_some_and(|c| c.is_empty()) {
        v.pop();
    }
    v
}

fn drive_prefix(s: &str) -> Option<(char, &str)> {
    let mut ch = s.chars();
    let d = ch.next()?;
    if d.is_ascii_alphabetic() && ch.next() == Some(':') {
        let rest = &s[2..];
        if rest.is_empty() || rest.starts_with('\\') {
            return Some((d.to_ascii_uppercase(), rest));
        }
    }
    None
}

pub fn parse_path(s: &str) -> WinPath {
    let raw = s.to_string();
    let (tag, body) = split_tag(s);
    let norm = body.replace('/', "\\");
    let n = norm.as_str();
    let mk = |kind, rest: &str| WinPath {
        kind,
        components: components(rest),
        tag: tag.clone(),
        raw: raw.clone(),
    };
    // \\.\ (Win32 device namespace) behaves like \\?\ for drive and volume paths; it is never a UNC share
    for vp in [r"\\?\", r"\??\", r"\\.\"] {
        if let Some(rest) = strip_ci(n, vp) {
            if let Some(r) = strip_ci(rest, r"UNC\") {
                return mk(PathKind::Unc, r);
            }
            if let Some((d, r)) = drive_prefix(rest) {
                return mk(PathKind::Drive(d), r);
            }
            if strip_ci(rest, "Volume{").is_some() {
                return mk(PathKind::VolumeGuid, rest);
            }
            return WinPath {
                kind: PathKind::Other,
                components: vec![n.to_string()],
                tag,
                raw,
            };
        }
    }
    if let Some(rest) = strip_ci(n, r"\Device\HarddiskVolume") {
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let tail = &rest[digits.len()..];
        if let (Ok(v), true) = (
            digits.parse::<u32>(),
            tail.is_empty() || tail.starts_with('\\'),
        ) {
            return mk(PathKind::Device(v), tail);
        }
    }
    if let Some(rest) = strip_ci(n, r"\SystemRoot")
        && (rest.is_empty() || rest.starts_with('\\'))
    {
        return mk(PathKind::SystemRoot, rest);
    }
    if let Some((d, r)) = drive_prefix(n) {
        return mk(PathKind::Drive(d), r);
    }
    if let Some(r) = n.strip_prefix(r"\\") {
        return mk(PathKind::Unc, r);
    }
    WinPath {
        kind: PathKind::Other,
        components: vec![n.to_string()],
        tag,
        raw,
    }
}

/// Ordinal upper-case per character; characters whose upper-case form expands are kept as-is.
/// Shared by PathKey and VolMap so both compare identically.
pub(crate) fn upper(s: &str) -> String {
    s.chars()
        .map(|c| {
            let mut u = c.to_uppercase();
            match (u.next(), u.next()) {
                (Some(x), None) => x,
                _ => c,
            }
        })
        .collect()
}

fn join(prefix: &str, comps: &[String]) -> String {
    let mut s = prefix.to_string();
    for c in comps {
        s.push('\\');
        s.push_str(&upper(c));
    }
    s
}

/// Identity key and its strength (Heuristic when a heuristic VolMap/SystemRoot mapping was used).
pub fn key_of(p: &WinPath, vm: &VolMap) -> (PathKey, Strength) {
    let (s, st) = match p.kind {
        PathKind::Drive(d) => (join(&format!("{d}:"), &p.components), Strength::Exact),
        PathKind::Device(n) => match vm.map.get(&n) {
            Some((d, st, _)) => (join(&format!("{d}:"), &p.components), *st),
            None => (
                join(&format!(r"\DEVICE\HARDDISKVOLUME{n}"), &p.components),
                Strength::Exact,
            ),
        },
        PathKind::SystemRoot => match vm.systemroot {
            Some((d, st)) => {
                let mut c = vec!["WINDOWS".to_string()];
                c.extend(p.components.iter().cloned());
                (join(&format!("{d}:"), &c), st)
            }
            None => (join(r"\SYSTEMROOT", &p.components), Strength::Exact),
        },
        PathKind::Unc => (format!("\\{}", join("", &p.components)), Strength::Exact),
        PathKind::VolumeGuid => (join(r"\\?", &p.components), Strength::Exact),
        PathKind::Other => (upper(&p.components.join("\\")), Strength::Exact),
    };
    (PathKey(s), st)
}

/// System = exactly `Windows`, `Program Files`, `Program Files (x86)` at the volume root (v1 rule).
pub fn loc_class(p: &WinPath, vm: &VolMap) -> LocClass {
    match p.kind {
        // %SystemRoot% is the Windows directory by definition.
        PathKind::SystemRoot => LocClass::SystemDir,
        PathKind::Device(n) if !vm.map.contains_key(&n) => LocClass::Unknown,
        PathKind::Drive(_) | PathKind::Device(_) => match p.components.first().map(|c| upper(c)) {
            Some(c) if c == "WINDOWS" || c == "PROGRAM FILES" || c == "PROGRAM FILES (X86)" => {
                LocClass::SystemDir
            }
            _ => LocClass::OutsideSystemDirs,
        },
        _ => LocClass::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{LocClass, Strength};
    use crate::normalize::volmap::VolMap;

    fn key(s: &str) -> PathKey {
        key_of(&parse_path(s), &VolMap::default()).0
    }

    #[test]
    fn same_file_spellings_one_key() {
        let k = key(r"C:\Tools\a.exe");
        for s in [
            r"\\?\C:\Tools\a.exe",
            r"\??\c:\tools\A.EXE",
            "C:/Tools/a.exe",
            r"ENG:OFNSET:c:\tools\a.exe",
        ] {
            assert_eq!(key(s), k, "{s}");
        }
        assert_eq!(k.0, r"C:\TOOLS\A.EXE");
        assert_eq!(
            parse_path(r"ENG:OFNSET:c:\tools\a.exe").tag.as_deref(),
            Some("ENG:OFNSET")
        );
    }

    #[test]
    fn unc_from_verbatim() {
        for s in [
            r"\\?\UNC\srv\share\x",
            r"\\srv\share\x",
            r"\??\UNC\srv\share\x",
        ] {
            let p = parse_path(s);
            assert_eq!(p.kind, PathKind::Unc, "{s}");
            assert_eq!(p.components, vec!["srv", "share", "x"]);
        }
        assert_eq!(key(r"\\?\UNC\srv\share\x").0, r"\\SRV\SHARE\X");
    }

    #[test]
    fn device_unmapped_key() {
        let p = parse_path(r"\Device\HarddiskVolume3\T\out.bin");
        assert_eq!(p.kind, PathKind::Device(3));
        let (k, s) = key_of(&p, &VolMap::default());
        assert_eq!(k.0, r"\DEVICE\HARDDISKVOLUME3\T\OUT.BIN");
        assert_eq!(s, Strength::Exact);
    }

    #[test]
    fn other_namespaces() {
        assert_eq!(
            parse_path(r"\SystemRoot\System32\drivers\x.sys").kind,
            PathKind::SystemRoot
        );
        assert_eq!(parse_path(r"\\?\Volume{1234}\x").kind, PathKind::VolumeGuid);
        assert_eq!(parse_path("processed").kind, PathKind::Other);
        assert_eq!(parse_path("").kind, PathKind::Other);
    }

    #[test]
    fn loc_class_boundaries() {
        let vm = VolMap::default();
        assert_eq!(
            loc_class(&parse_path(r"C:\Program Files Evil\x.exe"), &vm),
            LocClass::OutsideSystemDirs
        );
        assert_eq!(
            loc_class(&parse_path(r"C:\Windows\x.exe"), &vm),
            LocClass::SystemDir
        );
        assert_eq!(
            loc_class(&parse_path(r"C:\Program Files (x86)\x.exe"), &vm),
            LocClass::SystemDir
        );
        assert_eq!(
            loc_class(&parse_path(r"C:\WindowsApps\x.exe"), &vm),
            LocClass::OutsideSystemDirs
        );
        assert_eq!(
            loc_class(&parse_path(r"\SystemRoot\x.sys"), &vm),
            LocClass::SystemDir
        );
        assert_eq!(
            loc_class(&parse_path(r"\\srv\share\x"), &vm),
            LocClass::Unknown
        );
    }

    #[test]
    fn dot_segments_are_not_rewritten() {
        assert_eq!(key(r"C:\a\..\b.exe").0, r"C:\A\..\B.EXE");
        assert_ne!(key(r"\\srv\share\..\other\x"), key(r"\\srv\other\x"));
        assert_ne!(key(r"C:\Tools\.\a.exe"), key(r"C:\Tools\a.exe"));
    }

    #[test]
    fn drive_relative_is_not_absolute() {
        assert_eq!(parse_path(r"C:Windows\x.exe").kind, PathKind::Other);
        assert_ne!(key(r"C:Windows\x.exe"), key(r"C:\Windows\x.exe"));
        assert_eq!(parse_path("C:").kind, PathKind::Drive('C'));
    }

    #[test]
    fn whitespace_is_significant() {
        assert_ne!(key("\\\\?\\C:\\Tools\\a.exe "), key(r"\\?\C:\Tools\a.exe"));
    }

    #[test]
    fn unknown_namespace_keeps_prefix() {
        assert_ne!(
            key(r"\\?\GLOBALROOT\Device\HarddiskVolume3\x"),
            key(r"GLOBALROOT\Device\HarddiskVolume3\x")
        );
    }

    #[test]
    fn device_root_needs_boundary() {
        assert_eq!(
            parse_path(r"\Device\HarddiskVolume3evil\x").kind,
            PathKind::Other
        );
        assert_eq!(
            parse_path(r"\Device\HarddiskVolume3").kind,
            PathKind::Device(3)
        );
    }

    #[test]
    fn unmapped_device_location_unknown() {
        let vm = VolMap::default();
        assert_eq!(
            loc_class(&parse_path(r"\Device\HarddiskVolume3\Windows\x"), &vm),
            LocClass::Unknown
        );
        let mut m = VolMap::default();
        m.map.insert(3, ('C', Strength::Heuristic, vec![]));
        assert_eq!(
            loc_class(&parse_path(r"\Device\HarddiskVolume3\Windows\x"), &m),
            LocClass::SystemDir
        );
    }

    /// review #16: the Win32 device namespace \\.\ is never a UNC share.
    #[test]
    fn win32_device_namespace_is_not_unc() {
        assert_eq!(parse_path(r"\\.\C:\Tools\a.exe").kind, PathKind::Drive('C'));
        assert_eq!(parse_path(r"\\.\Volume{1234}\x").kind, PathKind::VolumeGuid);
        assert_eq!(parse_path(r"\\.\PhysicalDrive0").kind, PathKind::Other);
    }
}
