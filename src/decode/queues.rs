//! Rolling-queue decoders (spec §3 RollingQueues, §6 Queues). Malformed input never panics: it decodes as Generic.
use crate::history::store::parse_pid_start;
use crate::model::Ft;

#[derive(Clone, Debug, PartialEq)]
pub enum QueueFact {
    Threat {
        name: String,
        count: String,
    },
    Host {
        field: &'static str,
        value: String,
    },
    Process {
        pid: u32,
        start: Ft,
        suffix: String,
    },
    Dropped {
        path: String,
        script: bool,
    },
    Rdp {
        field: String,
        value: String,
    },
    RdpLogon {
        time: Option<Ft>,
        ip: String,
        user_sid: String,
        workstation: String,
        session: String,
    },
    Address {
        label: String,
        addr: u64,
    },
    Generic {
        key: String,
        value: String,
    },
}

fn generic(key: &str, value: &str) -> QueueFact {
    QueueFact::Generic {
        key: key.to_string(),
        value: value.to_string(),
    }
}

/// `Tact-pid:<N>,ProcessStart:<FT>[-suffix]` → (pid, start, suffix).
fn tact(name: &str) -> Option<(u32, Ft, String)> {
    let rest = name.strip_prefix("Tact-")?;
    let (pid, start) = parse_pid_start(rest)?;
    let after = rest.split_once("ProcessStart:")?.1;
    let tail = after.trim_start_matches(|c: char| c.is_ascii_digit());
    let suffix = match tail {
        "" => String::new(),
        t => t.strip_prefix('-').filter(|s| !s.is_empty())?.to_string(),
    };
    Some((pid, start, suffix))
}

fn json_str(v: &serde_json::Value, k: &str) -> String {
    match v.get(k) {
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    }
}

fn json_ft(v: &serde_json::Value, k: &str) -> Option<Ft> {
    match v.get(k)? {
        serde_json::Value::Number(n) => n.as_u64(),
        serde_json::Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// Present RDP fields must be strings or numbers, and `LT` must convert to a FILETIME.
fn rdp_fields_ok(v: &serde_json::Value) -> bool {
    let scalar = |k: &str| {
        matches!(
            v.get(k),
            None | Some(
                serde_json::Value::Null
                    | serde_json::Value::String(_)
                    | serde_json::Value::Number(_)
            )
        )
    };
    ["Wsn", "SLId", "Ip", "TSid", "LT"]
        .iter()
        .all(|k| scalar(k))
        && (v.get("LT").is_none() || json_ft(v, "LT").is_some())
}

fn parse_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => s.parse().ok(),
    }
}

pub fn decode_queue(table: &str, entry_key: &str, entry_value: &str) -> Vec<QueueFact> {
    if let Some((pid, start, suffix)) = tact(table).or_else(|| tact(entry_key)) {
        let mut v = vec![QueueFact::Process { pid, start, suffix }];
        if tact(entry_key).is_none() {
            v.push(generic(entry_key, entry_value));
        }
        return v;
    }
    match table {
        "RecentThreatsOnMachine" => vec![QueueFact::Threat {
            name: entry_key.into(),
            count: entry_value.into(),
        }],
        "domainInfo" => {
            if entry_key == "TCP-hostname" {
                return vec![QueueFact::Host {
                    field: "hostname",
                    value: entry_value.into(),
                }];
            }
            let is_v4 = entry_key.split('.').count() == 4
                && entry_key.split('.').all(|o| o.parse::<u8>().is_ok());
            match entry_value.trim().parse::<u64>() {
                Ok(f) if !entry_key.is_empty() => vec![QueueFact::Host {
                    field: if is_v4 { "ipv4" } else { "name" },
                    value: format!("{entry_key} (flags {f:#x}, meaning unverified)"),
                }],
                _ => vec![generic(entry_key, entry_value)],
            }
        }
        "RQ_RecentExecDropped" => vec![QueueFact::Dropped {
            path: entry_key.into(),
            script: false,
        }],
        "RQ_RecentScriptDropped" => vec![QueueFact::Dropped {
            path: entry_key.into(),
            script: true,
        }],
        "RDP-Event-Success" => match serde_json::from_str::<serde_json::Value>(entry_value) {
            Ok(v) if v.is_object() && rdp_fields_ok(&v) => vec![QueueFact::RdpLogon {
                time: json_ft(&v, "LT"),
                ip: json_str(&v, "Ip"),
                user_sid: json_str(&v, "SLId"),
                workstation: json_str(&v, "Wsn"),
                session: json_str(&v, "TSid"),
            }],
            _ => vec![generic(entry_key, entry_value)],
        },
        t if t.starts_with("RDP-") => vec![QueueFact::Rdp {
            field: t.into(),
            value: format!("{entry_key}={entry_value}"),
        }],
        "KernelCallBackAddress" => match (
            entry_key.starts_with("fn_AddressRange"),
            parse_addr(entry_value),
        ) {
            (true, Some(addr)) => vec![QueueFact::Address {
                label: entry_key.into(),
                addr,
            }],
            _ => vec![generic(entry_key, entry_value)],
        },
        _ => vec![generic(entry_key, entry_value)],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat() {
        assert_eq!(
            decode_queue("RecentThreatsOnMachine", "Behavior:Win32/Test.A", "1"),
            vec![QueueFact::Threat {
                name: "Behavior:Win32/Test.A".into(),
                count: "1".into()
            }]
        );
    }

    #[test]
    fn tact_pid() {
        let v = decode_queue(
            "Tact-pid:19788,ProcessStart:134368986477715047-amsifrag",
            "PS_ManageAuto",
            "3",
        );
        assert_eq!(
            v[0],
            QueueFact::Process {
                pid: 19788,
                start: 134368986477715047,
                suffix: "amsifrag".into()
            }
        );
        assert!(v.contains(&QueueFact::Generic {
            key: "PS_ManageAuto".into(),
            value: "3".into()
        }));
    }

    #[test]
    fn domain_info_real_shapes() {
        // Real shapes (reference copy): TCP-hostname=<host>; other keys are addresses / DNS suffixes with a flag value.
        assert_eq!(
            decode_queue("domainInfo", "TCP-hostname", "<HOST>"),
            vec![QueueFact::Host {
                field: "hostname",
                value: "<HOST>".into()
            }]
        );
        assert_eq!(
            decode_queue("domainInfo", "10.0.0.1", "2080"),
            vec![QueueFact::Host {
                field: "ipv4",
                value: "10.0.0.1 (flags 0x820, meaning unverified)".into()
            }]
        );
        assert_eq!(
            decode_queue("domainInfo", "lan", "8"),
            vec![QueueFact::Host {
                field: "name",
                value: "lan (flags 0x8, meaning unverified)".into()
            }]
        );
        assert_eq!(
            decode_queue("domainInfo", "x", "notnum"),
            vec![QueueFact::Generic {
                key: "x".into(),
                value: "notnum".into()
            }]
        );
    }

    #[test]
    fn dropped() {
        assert_eq!(
            decode_queue("RQ_RecentScriptDropped", r"c:\t\a.ps1", "1"),
            vec![QueueFact::Dropped {
                path: r"c:\t\a.ps1".into(),
                script: true
            }]
        );
    }

    #[test]
    fn rdp_event_json() {
        let j =
            r#"{"Wsn":"WS1","SLId":"S-1-5-21-1","LT":134369015368153546,"Ip":"10.0.0.5","TSid":2}"#;
        assert_eq!(
            decode_queue("RDP-Event-Success", "k", j),
            vec![QueueFact::RdpLogon {
                time: Some(134369015368153546),
                ip: "10.0.0.5".into(),
                user_sid: "S-1-5-21-1".into(),
                workstation: "WS1".into(),
                session: "2".into()
            }]
        );
        let s = r#"{"LT":"134369015368153546"}"#;
        assert!(matches!(
            &decode_queue("RDP-Event-Success", "k", s)[0],
            QueueFact::RdpLogon {
                time: Some(134369015368153546),
                ..
            }
        ));
    }

    #[test]
    fn rdp_event_bad_json_generic() {
        assert!(matches!(
            &decode_queue("RDP-Event-Success", "k", "{not json")[0],
            QueueFact::Generic { .. }
        ));
    }

    #[test]
    fn rdp_other_and_kernel_address() {
        assert_eq!(
            decode_queue("RDP-S-IPs", "10.0.0.5", "3"),
            vec![QueueFact::Rdp {
                field: "RDP-S-IPs".into(),
                value: "10.0.0.5=3".into()
            }]
        );
        assert_eq!(
            decode_queue(
                "KernelCallBackAddress",
                "fn_AddressRange_min",
                "140716164557072"
            ),
            vec![QueueFact::Address {
                label: "fn_AddressRange_min".into(),
                addr: 140716164557072
            }]
        );
        assert_eq!(
            decode_queue("KernelCallBackAddress", "Recorded_Time", "51781"),
            vec![QueueFact::Generic {
                key: "Recorded_Time".into(),
                value: "51781".into()
            }]
        );
    }

    #[test]
    fn rdp_event_wrong_field_types_generic() {
        assert!(matches!(
            &decode_queue("RDP-Event-Success", "k", r#"{"LT":{},"Ip":[]}"#)[0],
            QueueFact::Generic { .. }
        ));
    }

    #[test]
    fn tact_with_trailing_junk_is_generic() {
        let v = decode_queue("Tact-pid:42,ProcessStart:134368986477715047.5", "k", "v");
        assert!(
            v.iter().all(|f| !matches!(f, QueueFact::Process { .. })),
            "{v:?}"
        );
    }

    #[test]
    fn unknown_table_generic() {
        assert_eq!(
            decode_queue("Whatever", "k", "v"),
            vec![QueueFact::Generic {
                key: "k".into(),
                value: "v".into()
            }]
        );
    }
}
