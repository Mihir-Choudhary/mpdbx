//! Device-volume → drive-letter mapping, inferred heuristically or asserted by the analyst (spec §5.1).
use crate::model::Strength;
use crate::normalize::path::{PathKind, WinPath, upper};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct VolMap {
    /// Device N → (drive, strength, supporting volume-relative paths)
    pub map: BTreeMap<u32, (char, Strength, Vec<String>)>,
    pub systemroot: Option<(char, Strength)>,
}

fn rel(p: &WinPath) -> String {
    p.components
        .iter()
        .map(|c| upper(c))
        .collect::<Vec<_>>()
        .join("\\")
}

/// Device N → X accepted when ≥ 2 distinct full volume-relative paths of N equal X paths and no other drive
/// shares any path with N. Inferred mappings are Heuristic; analyst assertions are Exact and win.
pub fn infer_volmap(paths: &[WinPath], asserted: &[(u32, char)]) -> VolMap {
    let mut dev: HashMap<u32, HashSet<String>> = HashMap::new();
    let mut drv: HashMap<char, HashSet<String>> = HashMap::new();
    for p in paths {
        if p.components.is_empty() {
            continue;
        }
        match p.kind {
            PathKind::Device(n) => {
                dev.entry(n).or_default().insert(rel(p));
            }
            PathKind::Drive(d) => {
                drv.entry(d).or_default().insert(rel(p));
            }
            _ => {}
        }
    }
    let mut vm = VolMap::default();
    for (n, dp) in &dev {
        let mut hits: Vec<(char, Vec<String>)> = drv
            .iter()
            .map(|(d, xp)| {
                let mut common: Vec<String> = dp.intersection(xp).cloned().collect();
                common.sort();
                (*d, common)
            })
            .filter(|(_, c)| !c.is_empty())
            .collect();
        if hits.len() == 1 && hits[0].1.len() >= 2 {
            let (d, mut support) = hits.remove(0);
            support.truncate(5);
            vm.map.insert(*n, (d, Strength::Heuristic, support));
        }
    }
    for &(n, d) in asserted {
        vm.map.insert(
            n,
            (
                d.to_ascii_uppercase(),
                Strength::Exact,
                vec!["analyst assertion".into()],
            ),
        );
    }
    let win: Vec<char> = drv
        .iter()
        .filter(|(_, ps)| {
            ps.iter()
                .any(|p| p == "WINDOWS" || p.starts_with("WINDOWS\\"))
        })
        .map(|(d, _)| *d)
        .collect();
    if win.len() == 1 {
        vm.systemroot = Some((win[0], Strength::Heuristic));
    }
    vm
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Strength;
    use crate::normalize::path::{key_of, parse_path};

    fn paths(v: &[&str]) -> Vec<crate::normalize::path::WinPath> {
        v.iter().map(|s| parse_path(s)).collect()
    }

    #[test]
    fn volmap_two_paths_infers_heuristic() {
        let p = paths(&[
            r"\Device\HarddiskVolume3\T\a.exe",
            r"\Device\HarddiskVolume3\T\b.exe",
            r"C:\T\a.exe",
            r"C:\T\b.exe",
        ]);
        let vm = infer_volmap(&p, &[]);
        assert_eq!(
            vm.map.get(&3).map(|m| (m.0, m.1)),
            Some(('C', Strength::Heuristic))
        );
        let (k, s) = key_of(&p[0], &vm);
        assert_eq!(k.0, r"C:\T\A.EXE");
        assert_eq!(s, Strength::Heuristic);
    }

    #[test]
    fn volmap_one_path_is_not_enough() {
        let vm = infer_volmap(
            &paths(&[r"\Device\HarddiskVolume3\T\a.exe", r"C:\T\a.exe"]),
            &[],
        );
        assert!(vm.map.is_empty());
    }

    #[test]
    fn volmap_contradiction_rejected() {
        let p = paths(&[
            r"\Device\HarddiskVolume3\T\a.exe",
            r"\Device\HarddiskVolume3\T\b.exe",
            r"\Device\HarddiskVolume3\U\c.exe",
            r"C:\T\a.exe",
            r"C:\T\b.exe",
            r"D:\U\c.exe",
        ]);
        assert!(infer_volmap(&p, &[]).map.is_empty());
    }

    #[test]
    fn volmap_uses_same_folding_as_pathkey() {
        let p = paths(&[
            r"\Device\HarddiskVolume3\ß\a",
            r"\Device\HarddiskVolume3\ß\b",
            r"C:\SS\a",
            r"C:\SS\b",
        ]);
        assert!(infer_volmap(&p, &[]).map.is_empty());
    }

    #[test]
    fn volmap_assertion_exact() {
        let vm = infer_volmap(&paths(&[r"\Device\HarddiskVolume7\x"]), &[(7, 'D')]);
        assert_eq!(
            vm.map.get(&7).map(|m| (m.0, m.1)),
            Some(('D', Strength::Exact))
        );
    }

    #[test]
    fn systemroot_maps_to_unique_windows_drive() {
        let p = paths(&[
            r"C:\Windows\System32\a.dll",
            r"\SystemRoot\System32\drivers\x.sys",
        ]);
        let vm = infer_volmap(&p, &[]);
        assert_eq!(vm.systemroot, Some(('C', Strength::Heuristic)));
        let (k, s) = key_of(&p[1], &vm);
        assert_eq!(k.0, r"C:\WINDOWS\SYSTEM32\DRIVERS\X.SYS");
        assert_eq!(s, Strength::Heuristic);
    }
}
