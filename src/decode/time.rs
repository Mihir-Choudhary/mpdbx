//! FILETIME classification, time-zone formatting and parsing (spec §6).
use crate::model::Ft;

/// v1 plausibility bounds: 1970-01-01 ≤ t < 2076 (spec §6).
pub const PLAUSIBLE_MIN: i64 = 116_444_736_000_000_000;
pub const PLAUSIBLE_MAX: i64 = 150_000_000_000_000_000;
/// 9999-12-31 23:59:59.9999999
pub const REPRESENTABLE_MAX: i64 = 2_650_467_743_999_999_999;
const TICKS_PER_SEC: i128 = 10_000_000;
const TICKS_PER_DAY: i128 = 86_400 * TICKS_PER_SEC;
/// Days from 1601-01-01 to 1970-01-01.
const DAYS_1601_TO_1970: i64 = 134_774;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FtClass {
    Zero,
    Max,
    Plausible(Ft),
    Representable(Ft),
    Opaque,
}

pub fn classify_ft(v: i64) -> FtClass {
    match v {
        0 => FtClass::Zero,
        -1 | i64::MAX => FtClass::Max,
        v if v < 0 => FtClass::Opaque,
        v if (PLAUSIBLE_MIN..PLAUSIBLE_MAX).contains(&v) => FtClass::Plausible(v as Ft),
        v if v <= REPRESENTABLE_MAX => FtClass::Representable(v as Ft),
        _ => FtClass::Opaque,
    }
}

/// Display zone: UTC (0) or a fixed analyst-entered offset; no DST rules.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Tz {
    pub offset_min: i32,
}

impl Tz {
    pub fn suffix(&self) -> String {
        if self.offset_min == 0 {
            return "Z".into();
        }
        let a = self.offset_min.abs();
        format!(
            "{}{:02}:{:02}",
            if self.offset_min < 0 { '-' } else { '+' },
            a / 60,
            a % 60
        )
    }
}

/// Howard Hinnant's days_from_civil (days since 1970-01-01).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn days_in_month(y: i64, m: i64) -> i64 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        _ => 0,
    }
}

/// `YYYY-MM-DD HH:MM:SS.fffffff` plus `Z` or `±HH:MM`. Values outside the representable range are printed raw.
pub fn fmt_ft(t: Ft, tz: Tz) -> String {
    let local = t as i128 + tz.offset_min as i128 * 60 * TICKS_PER_SEC;
    if local < 0 || local > REPRESENTABLE_MAX as i128 {
        return format!("{t} (raw)");
    }
    let days = (local / TICKS_PER_DAY) as i64;
    let rem = local % TICKS_PER_DAY;
    let (y, m, d) = civil_from_days(days - DAYS_1601_TO_1970);
    let secs = rem / TICKS_PER_SEC;
    let frac = rem % TICKS_PER_SEC;
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{frac:07}{}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60,
        tz.suffix()
    )
}

fn num(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// `Z`, `UTC`, `+HH:MM`, `-HH:MM` with |offset| ≤ 14:00.
pub fn parse_tz(s: &str) -> Option<Tz> {
    let s = s.trim();
    if !s.is_ascii() {
        return None;
    }
    if s.eq_ignore_ascii_case("z") || s.eq_ignore_ascii_case("utc") {
        return Some(Tz { offset_min: 0 });
    }
    let (sign, rest) = match s.as_bytes().first()? {
        b'+' => (1, &s[1..]),
        b'-' => (-1, &s[1..]),
        _ => return None,
    };
    let (h, m) = rest.split_once(':')?;
    if h.len() != 2 || m.len() != 2 {
        return None;
    }
    let (h, m) = (num(h)?, num(m)?);
    let total = h * 60 + m;
    if m >= 60 || total > 14 * 60 {
        return None;
    }
    Some(Tz {
        offset_min: (sign * total) as i32,
    })
}

/// ISO 8601 subset `YYYY-MM-DD[(T| )HH:MM[:SS[.f{1,7}]]][Z|±HH:MM]`; an explicit offset wins over `tz`.
pub fn parse_time(s: &str, tz: Tz) -> Option<Ft> {
    let s = s.trim();
    if s.len() < 10 || !s.is_ascii() {
        return None;
    }
    let (date, rest) = s.split_at(10);
    let mut dp = date.split('-');
    let (y, mo, d) = (num(dp.next()?)?, num(dp.next()?)?, num(dp.next()?)?);
    if dp.next().is_some()
        || !(1601..=9999).contains(&y)
        || !(1..=12).contains(&mo)
        || d < 1
        || d > days_in_month(y, mo)
    {
        return None;
    }
    let mut rest = rest;
    let mut zone = tz;
    // trailing zone
    if let Some(r) = rest.strip_suffix('Z').or_else(|| rest.strip_suffix('z')) {
        zone = Tz { offset_min: 0 };
        rest = r;
    } else if rest.len() >= 6 {
        let (body, tail) = rest.split_at(rest.len() - 6);
        if (tail.starts_with('+') || tail.starts_with('-')) && tail.as_bytes()[3] == b':' {
            zone = parse_tz(tail)?;
            rest = body;
        }
    }
    let mut ticks: i128 = 0;
    if !rest.is_empty() {
        let t = rest.strip_prefix('T').or_else(|| rest.strip_prefix(' '))?;
        let (hms, frac) = match t.split_once('.') {
            Some((a, b)) => (a, Some(b)),
            None => (t, None),
        };
        let parts: Vec<&str> = hms.split(':').collect();
        if !(2..=3).contains(&parts.len()) || parts.iter().any(|p| p.len() != 2) {
            return None;
        }
        let h = num(parts[0])?;
        let mi = num(parts[1])?;
        let se = if parts.len() == 3 { num(parts[2])? } else { 0 };
        if h > 23 || mi > 59 || se > 59 {
            return None;
        }
        if frac.is_some() && parts.len() != 3 {
            return None;
        }
        ticks += ((h * 3600 + mi * 60 + se) as i128) * TICKS_PER_SEC;
        if let Some(f) = frac {
            if f.is_empty() || f.len() > 7 {
                return None;
            }
            let v = num(f)? as i128;
            ticks += v * 10i128.pow(7 - f.len() as u32);
        }
    }
    let days = days_from_civil(y, mo, d) + DAYS_1601_TO_1970;
    let utc = days as i128 * TICKS_PER_DAY + ticks - zone.offset_min as i128 * 60 * TICKS_PER_SEC;
    if utc < 0 || utc > REPRESENTABLE_MAX as i128 {
        return None;
    }
    Some(utc as Ft)
}

/// SQLite TEXT dates `YYYY-MM-DD[ HH:MM:SS]`, interpreted as UTC.
pub fn parse_sql_text_time(s: &str) -> Option<Ft> {
    parse_time(s, Tz { offset_min: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;
    const UTC: Tz = Tz { offset_min: 0 };
    const IST: Tz = Tz { offset_min: 330 };

    #[test]
    fn ft_example() {
        assert_eq!(
            fmt_ft(134369015368153546, UTC),
            "2026-10-19 16:38:56.8153546Z"
        );
    }

    #[test]
    fn ft_offset() {
        assert_eq!(
            fmt_ft(134369015368153546, IST),
            "2026-10-19 22:08:56.8153546+05:30"
        );
        assert_eq!(
            fmt_ft(134369015368153546, Tz { offset_min: -300 }),
            "2026-10-19 11:38:56.8153546-05:00"
        );
    }

    #[test]
    fn ft_classes() {
        assert_eq!(classify_ft(0), FtClass::Zero);
        assert_eq!(classify_ft(-1), FtClass::Max);
        assert_eq!(classify_ft(i64::MAX), FtClass::Max);
        assert_eq!(
            classify_ft(116444736000000000),
            FtClass::Plausible(116444736000000000)
        );
        assert_eq!(
            classify_ft(149999999999999999),
            FtClass::Plausible(149999999999999999)
        );
        assert_eq!(
            classify_ft(150000000000000000),
            FtClass::Representable(150000000000000000)
        );
        assert_eq!(classify_ft(42), FtClass::Representable(42));
        assert_eq!(
            classify_ft(2650467743999999999),
            FtClass::Representable(2650467743999999999)
        );
        assert_eq!(classify_ft(2650467744000000000), FtClass::Opaque);
        assert_eq!(classify_ft(i64::MIN), FtClass::Opaque);
    }

    #[test]
    fn parse_time_explicit_offset_wins() {
        assert_eq!(
            parse_time("2026-10-19T22:08:56+05:30", UTC),
            Some(134369015360000000)
        );
        assert_eq!(
            parse_time("2026-10-19T16:38:56Z", IST),
            Some(134369015360000000)
        );
    }

    #[test]
    fn parse_time_uses_tz() {
        assert_eq!(
            parse_time("2026-10-19 16:38", IST),
            Some(134368816800000000)
        );
        assert_eq!(parse_time("2026-10-19", UTC), Some(134368416000000000));
        assert_eq!(
            parse_time("2026-10-19 16:38:56.8153546", UTC),
            Some(134369015368153546)
        );
    }

    #[test]
    fn parse_time_rejects_garbage() {
        for s in [
            "",
            "notadate",
            "2026-13-01",
            "2026-02-30",
            "2026-10-19 25:00",
            "2026-10-19T16:38+15:00",
            "2026-10-19 16:38:56.12345678",
        ] {
            assert_eq!(parse_time(s, UTC), None, "{s}");
        }
    }

    #[test]
    fn parse_time_non_ascii_returns_none() {
        assert_eq!(parse_time("2026-11-0é", UTC), None);
        assert_eq!(parse_time("2026-11-09Té12345", UTC), None);
        assert_eq!(parse_sql_text_time("2026-11-0é"), None);
        assert_eq!(parse_tz("+é:00"), None);
    }

    #[test]
    fn tz_parsing() {
        assert_eq!(parse_tz("Z"), Some(UTC));
        assert_eq!(parse_tz("utc"), Some(UTC));
        assert_eq!(parse_tz("+05:30"), Some(IST));
        assert_eq!(parse_tz("-08:00"), Some(Tz { offset_min: -480 }));
        assert_eq!(parse_tz("+14:30"), None);
        assert_eq!(parse_tz("0530"), None);
    }

    #[test]
    fn sql_text_time() {
        assert_eq!(
            parse_sql_text_time("2026-10-19 16:38:56"),
            Some(134369015360000000)
        );
        assert_eq!(parse_sql_text_time("2026-10-19"), Some(134368416000000000));
        assert_eq!(parse_sql_text_time("garbage"), None);
    }

    #[test]
    fn roundtrip_format_parse() {
        let t = 134369015368153546;
        assert_eq!(parse_time(&fmt_ft(t, IST), UTC), Some(t));
    }
}
