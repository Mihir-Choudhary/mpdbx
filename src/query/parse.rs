//! Search syntax (spec §7). Terms are AND-combined; `-term` negates; quotes group.
use crate::decode::time::{Tz, parse_time};
use crate::model::{DbStatus, DigestAlg, Ft, LocClass};

/// Case-insensitive glob (`*`, `?`); a pattern without wildcards matches as a substring.
#[derive(Clone, Debug)]
pub struct Glob {
    pat: Vec<char>,
    wild: bool,
}

impl Glob {
    pub fn new(p: &str) -> Self {
        let pat: Vec<char> = p.to_lowercase().chars().collect();
        let wild = pat.iter().any(|c| *c == '*' || *c == '?');
        Glob { pat, wild }
    }

    pub fn matches(&self, s: &str) -> bool {
        self.matches_lower(&s.to_lowercase())
    }

    /// `s` must already be lower-case.
    pub fn matches_lower(&self, s: &str) -> bool {
        if s.is_ascii() && self.pat.iter().all(char::is_ascii) {
            let p: Vec<u8> = self.pat.iter().map(|c| *c as u8).collect();
            return glob_bytes(&p, s.as_bytes(), self.wild);
        }
        let s: Vec<char> = s.chars().collect();
        if !self.wild {
            return s
                .windows(self.pat.len().max(1))
                .any(|w| w == self.pat.as_slice())
                || self.pat.is_empty();
        }
        // iterative glob with backtracking on the last '*'
        let (mut i, mut j, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
        while i < s.len() {
            if j < self.pat.len() && (self.pat[j] == '?' || self.pat[j] == s[i]) {
                i += 1;
                j += 1;
            } else if j < self.pat.len() && self.pat[j] == '*' {
                star = Some(j);
                mark = i;
                j += 1;
            } else if let Some(st) = star {
                j = st + 1;
                mark += 1;
                i = mark;
            } else {
                return false;
            }
        }
        while j < self.pat.len() && self.pat[j] == '*' {
            j += 1;
        }
        j == self.pat.len()
    }
}

fn glob_bytes(p: &[u8], s: &[u8], wild: bool) -> bool {
    if !wild {
        return p.is_empty() || s.windows(p.len()).any(|w| w == p);
    }
    let (mut i, mut j, mut star, mut mark) = (0usize, 0usize, None::<usize>, 0usize);
    while i < s.len() {
        if j < p.len() && (p[j] == b'?' || p[j] == s[i]) {
            i += 1;
            j += 1;
        } else if j < p.len() && p[j] == b'*' {
            star = Some(j);
            mark = i;
            j += 1;
        } else if let Some(st) = star {
            j = st + 1;
            mark += 1;
            i = mark;
        } else {
            return false;
        }
    }
    while j < p.len() && p[j] == b'*' {
        j += 1;
    }
    j == p.len()
}

#[derive(Clone, Debug)]
pub enum Term {
    Text(String),
    Path(Glob),
    Name(Glob),
    /// Glob over lower-case hex; a value without wildcards matches as a prefix.
    Digest(DigestAlg, Glob),
    Pid(u32),
    /// Glob over the event-type name (substring when no wildcards).
    Type(Glob),
    Src(DbStatus),
    Loc(LocClass),
    NoCert,
    After(Ft),
    Before(Ft),
    Regex(regex_lite::Regex),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QErr {
    pub pos: usize,
    pub msg: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tok {
    /// May be `key:value`.
    Plain,
    /// `/…/`
    Regex,
    /// A quote opened before any `:`, so the token is free text even if it contains `key:` (`"pid:4120,…"`).
    Literal,
}

/// Splits into (byte position, negated, token, kind) honouring double quotes (also after `key:`).
/// A token starting with `/` runs to the next `/` that ends the token (followed by whitespace or the end);
/// its content is kept verbatim, spaces and quotes included.
fn tokens(s: &str) -> Result<Vec<(usize, bool, String, Tok)>, QErr> {
    let mut out = Vec::new();
    let cs: Vec<(usize, char)> = s.char_indices().collect();
    let mut k = 0;
    while k < cs.len() {
        if cs[k].1.is_whitespace() {
            k += 1;
            continue;
        }
        let start = cs[k].0;
        let mut neg = false;
        if cs[k].1 == '-' && k + 1 < cs.len() && !cs[k + 1].1.is_whitespace() {
            neg = true;
            k += 1;
        }
        if cs[k].1 == '/' {
            let close = (k + 1..cs.len())
                .find(|&j| cs[j].1 == '/' && cs.get(j + 1).is_none_or(|c| c.1.is_whitespace()));
            if let Some(j) = close {
                out.push((
                    start,
                    neg,
                    cs[k + 1..j].iter().map(|c| c.1).collect(),
                    Tok::Regex,
                ));
                k = j + 1;
                continue;
            }
        }
        let mut tok = String::new();
        let mut quoted = false;
        let mut kind = Tok::Plain;
        let mut key_seen = false;
        while k < cs.len() && (quoted || !cs[k].1.is_whitespace()) {
            match cs[k].1 {
                '"' => {
                    if !key_seen {
                        kind = Tok::Literal;
                    }
                    quoted = !quoted
                }
                c => {
                    if c == ':' {
                        key_seen = true;
                    }
                    tok.push(c)
                }
            }
            k += 1;
        }
        if quoted {
            return Err(QErr {
                pos: start,
                msg: "unterminated quote".into(),
            });
        }
        out.push((start, neg, tok, kind));
    }
    Ok(out)
}

fn digest_glob(v: &str) -> Glob {
    if v.contains(['*', '?']) {
        Glob::new(v)
    } else {
        Glob::new(&format!("{v}*"))
    }
}

pub fn parse(s: &str, tz: Tz) -> Result<Vec<(bool, Term)>, QErr> {
    let mut out = Vec::new();
    for (pos, neg, tok, kind) in tokens(s)? {
        let err = |msg: String| QErr { pos, msg };
        if kind == Tok::Literal {
            out.push((neg, Term::Text(tok.to_lowercase())));
            continue;
        }
        if kind == Tok::Regex {
            let re = regex_lite::Regex::new(&format!("(?i){tok}"))
                .map_err(|e| err(format!("bad regex: {e}")))?;
            out.push((neg, Term::Regex(re)));
            continue;
        }
        let term = match tok.split_once(':') {
            Some((key, v)) => match key.to_ascii_lowercase().as_str() {
                "path" => Term::Path(Glob::new(v)),
                "name" => Term::Name(Glob::new(v)),
                "sha256" => Term::Digest(DigestAlg::Sha256, digest_glob(v)),
                "sha1" => Term::Digest(DigestAlg::Sha1, digest_glob(v)),
                "md5" => Term::Digest(DigestAlg::Md5, digest_glob(v)),
                "pid" => Term::Pid(
                    v.parse()
                        .map_err(|_| err(format!("pid:{v} is not a number")))?,
                ),
                "type" => Term::Type(Glob::new(v)),
                "src" => Term::Src(match v.to_ascii_lowercase().as_str() {
                    "db" => DbStatus::InBoth,
                    "walonly" | "wal" => DbStatus::WalOnly,
                    "walmod" => DbStatus::WalModified,
                    "removed" => DbStatus::RemovedByWal,
                    "unknown" => DbStatus::Unknown,
                    _ => {
                        return Err(err(format!(
                            "src:{v} — use db, walonly, walmod, removed, unknown"
                        )));
                    }
                }),
                "loc" => Term::Loc(match v.to_ascii_lowercase().as_str() {
                    "system" => LocClass::SystemDir,
                    "outside" => LocClass::OutsideSystemDirs,
                    "unknown" => LocClass::Unknown,
                    _ => return Err(err(format!("loc:{v} — use system, outside, unknown"))),
                }),
                "nocert" if v.eq_ignore_ascii_case("yes") => Term::NoCert,
                "nocert" => return Err(err("nocert: takes only 'yes'".into())),
                "after" => Term::After(
                    parse_time(v, tz)
                        .ok_or_else(|| err(format!("after:{v} is not a date/time")))?,
                ),
                "before" => Term::Before(
                    parse_time(v, tz)
                        .ok_or_else(|| err(format!("before:{v} is not a date/time")))?,
                ),
                _ => Term::Text(tok.to_lowercase()),
            },
            None => Term::Text(tok.to_lowercase()),
        };
        out.push((neg, term));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::time::Tz;

    /// A value quoted from its first character is free text even when it looks like `key:value` (the Inspector's
    /// "filter" button quotes field values such as `pid:4120,ProcessStart:…`); a quote after `key:` still groups the value.
    #[test]
    fn quoted_token_is_literal_text() {
        let t = parse(
            r#""pid:4120,ProcessStart:134369015368153546" -"src:x" path:"C:\Program Files\*""#,
            Tz::default(),
        )
        .unwrap();
        assert!(
            matches!(&t[0], (false, Term::Text(x)) if x == "pid:4120,processstart:134369015368153546")
        );
        assert!(matches!(&t[1], (true, Term::Text(x)) if x == "src:x"));
        assert!(matches!(&t[2], (false, Term::Path(_))));
        assert!(
            parse("pid:abc", Tz::default()).is_err(),
            "unquoted keys still validate"
        );
    }

    #[test]
    fn parse_terms() {
        let t = parse(
            r"path:c:\t\* -type:module nocert:yes after:2026-10-19",
            Tz::default(),
        )
        .unwrap();
        assert_eq!(t.len(), 4);
        assert!(matches!(&t[0], (false, Term::Path(_))));
        assert!(matches!(&t[1], (true, Term::Type(g)) if g.matches("modulefirstload")));
        assert!(matches!(&t[2], (false, Term::NoCert)));
        assert!(matches!(&t[3], (false, Term::After(134368416000000000))));
    }

    #[test]
    fn quoted_text_and_quoted_values() {
        let t = parse(r#""a b" c path:"C:\Program Files\*""#, Tz::default()).unwrap();
        assert!(matches!(&t[0], (false, Term::Text(s)) if s == "a b"));
        assert!(matches!(&t[1], (false, Term::Text(s)) if s == "c"));
        assert!(matches!(&t[2], (false, Term::Path(g)) if g.matches(r"c:\program files\x.exe")));
    }

    #[test]
    fn parse_error_position() {
        let e = parse("foo after:notadate", Tz::default()).unwrap_err();
        assert_eq!(e.pos, 4);
        assert!(parse("pid:abc", Tz::default()).is_err());
        assert!(parse("src:nope", Tz::default()).is_err());
        assert!(parse(r#""unterminated"#, Tz::default()).is_err());
    }

    #[test]
    fn regex_term_and_drive_colon_is_text() {
        let t = parse(r"/Foo.*bar/ c:\x", Tz::default()).unwrap();
        assert!(matches!(&t[0], (false, Term::Regex(r)) if r.is_match("xxfooQQbar")));
        assert!(matches!(&t[1], (false, Term::Text(s)) if s == r"c:\x"));
        assert!(parse("/[/", Tz::default()).is_err());
    }

    #[test]
    fn glob_semantics() {
        assert!(Glob::new(r"c:\t\*").matches(r"c:\t\a.exe"));
        assert!(!Glob::new(r"c:\t\*.dll").matches(r"c:\t\a.exe"));
        assert!(Glob::new("a?c").matches("abc"));
        assert!(
            Glob::new("tools").matches(r"c:\tools\x"),
            "no wildcard = substring"
        );
        assert!(Glob::new("A*").matches("abc"), "case-insensitive");
    }

    #[test]
    fn src_and_loc_values() {
        let t = parse(
            "src:walonly src:removed src:db loc:outside sha256:ABCD",
            Tz::default(),
        )
        .unwrap();
        assert!(matches!(t[0].1, Term::Src(crate::model::DbStatus::WalOnly)));
        assert!(matches!(
            t[1].1,
            Term::Src(crate::model::DbStatus::RemovedByWal)
        ));
        assert!(matches!(t[2].1, Term::Src(crate::model::DbStatus::InBoth)));
        assert!(matches!(
            t[3].1,
            Term::Loc(crate::model::LocClass::OutsideSystemDirs)
        ));
        assert!(
            matches!(&t[4].1, Term::Digest(crate::model::DigestAlg::Sha256, g) if g.matches("abcd1234") && !g.matches("1abcd"))
        );
    }
}
