//! Output-path safety: exports may never overwrite evidence (spec §4, §9 exit 5).
use crate::evidence::{Input, file_identity};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardError {
    IsInput,
    Exists,
    Escapes,
    Io(String),
}

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardError::IsInput => {
                write!(f, "refused: the target is one of the evidence input files")
            }
            GuardError::Exists => write!(
                f,
                "refused: the target exists (use --force or confirm overwrite)"
            ),
            GuardError::Escapes => {
                write!(f, "refused: the file name would leave the output directory")
            }
            GuardError::Io(e) => write!(f, "I/O error: {e}"),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct OutputGuard {
    inputs: Vec<(u32, u64)>,
    /// Canonical paths of every input (fallback when an identity cannot be established).
    paths: Vec<PathBuf>,
}

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

impl OutputGuard {
    pub fn new(inputs: &[&Input]) -> Self {
        OutputGuard {
            inputs: inputs
                .iter()
                .filter_map(|i| i.identity.or_else(|| file_identity(&i.path)))
                .collect(),
            paths: inputs
                .iter()
                .map(|i| std::fs::canonicalize(&i.path).unwrap_or_else(|_| i.path.clone()))
                .collect(),
        }
    }

    /// Ok when `target` does not exist, or exists, is not an input, and `force` is set.
    pub fn check_file(&self, target: &Path, force: bool) -> Result<(), GuardError> {
        if !target.exists() {
            return Ok(());
        }
        if let Ok(c) = std::fs::canonicalize(target) {
            if self.paths.iter().any(|p| p == &c) {
                return Err(GuardError::IsInput);
            }
        }
        match file_identity(target) {
            Some(id) if self.inputs.contains(&id) => Err(GuardError::IsInput),
            None => Err(GuardError::Io(format!(
                "cannot identify {}",
                target.display()
            ))),
            Some(_) if !force => Err(GuardError::Exists),
            Some(_) => Ok(()),
        }
    }

    pub fn is_input_identity(&self, id: (u32, u64)) -> bool {
        self.inputs.contains(&id)
    }

    /// `dir` joined with a sanitised single-component `name`.
    pub fn child(&self, dir: &Path, name: &str) -> Result<PathBuf, GuardError> {
        if name.split(['\\', '/']).any(|c| c == "..") {
            return Err(GuardError::Escapes);
        }
        let mut s: String = name
            .chars()
            .map(|c| {
                if c.is_control() || "<>:\"/\\|?*".contains(c) {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        while s.ends_with('.') || s.ends_with(' ') {
            s.pop();
        }
        if s.is_empty() || s == "." {
            return Err(GuardError::Escapes);
        }
        let stem = s
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end()
            .to_ascii_uppercase();
        if RESERVED.contains(&stem.as_str()) {
            s.insert(0, '_');
        }
        let p = dir.join(&s);
        if p.parent() != Some(dir) {
            return Err(GuardError::Escapes);
        }
        Ok(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{read_input, tests::tmpdir};

    #[test]
    fn guard_refuses_input_by_identity() {
        let d = tmpdir("g1");
        let p = d.join("mpenginedb.db");
        std::fs::write(&p, b"evidence").unwrap();
        std::fs::create_dir_all(d.join("sub")).unwrap();
        std::fs::hard_link(&p, d.join("link.db")).unwrap();
        let inp = read_input(&p, 1 << 20).unwrap();
        let g = OutputGuard::new(&[&inp]);
        assert_eq!(g.check_file(&p, true), Err(GuardError::IsInput));
        assert_eq!(
            g.check_file(&d.join("sub").join("..").join("mpenginedb.db"), true),
            Err(GuardError::IsInput)
        );
        assert_eq!(
            g.check_file(&d.join("link.db"), true),
            Err(GuardError::IsInput)
        );
        assert_eq!(std::fs::read(&p).unwrap(), b"evidence");
    }

    #[test]
    fn guard_protects_input_without_identity() {
        let d = tmpdir("g5");
        let p = d.join("in.db");
        std::fs::write(&p, b"e").unwrap();
        let mut inp = read_input(&p, 1 << 20).unwrap();
        inp.identity = None;
        let g = OutputGuard::new(&[&inp]);
        assert_eq!(g.check_file(&p, true), Err(GuardError::IsInput));
    }

    #[test]
    fn guard_refuses_existing_without_force() {
        let d = tmpdir("g2");
        std::fs::write(d.join("out.csv"), b"old").unwrap();
        let g = OutputGuard::new(&[]);
        assert_eq!(
            g.check_file(&d.join("out.csv"), false),
            Err(GuardError::Exists)
        );
    }

    #[test]
    fn guard_allows_existing_with_force_and_new_files() {
        let d = tmpdir("g3");
        std::fs::write(d.join("out.csv"), b"old").unwrap();
        let g = OutputGuard::new(&[]);
        assert_eq!(g.check_file(&d.join("out.csv"), true), Ok(()));
        assert_eq!(g.check_file(&d.join("new.csv"), false), Ok(()));
    }

    #[test]
    fn child_sanitises_and_confines() {
        let d = tmpdir("g4");
        let g = OutputGuard::new(&[]);
        assert_eq!(g.child(&d, "..\\evil"), Err(GuardError::Escapes));
        assert_eq!(g.child(&d, ".."), Err(GuardError::Escapes));
        assert_eq!(g.child(&d, "a:b?.csv").unwrap(), d.join("a_b_.csv"));
        assert_eq!(g.child(&d, "CON.csv").unwrap(), d.join("_CON.csv"));
        assert_eq!(g.child(&d, "x. ").unwrap(), d.join("x"));
    }
}
