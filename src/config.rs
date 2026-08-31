use ipnet::IpNet;

pub const MAX_PREFIXES: usize = 16;

pub fn parse_prefixes(raw: &str) -> Result<Vec<IpNet>, String> {
    let mut prefixes = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let net: IpNet = part
            .parse()
            .map_err(|e| format!("invalid CIDR {part:?}: {e}"))?;
        prefixes.push(net.trunc());
    }
    if prefixes.is_empty() {
        return Err("need at least one CIDR".into());
    }
    if prefixes.len() > MAX_PREFIXES {
        return Err(format!("at most {MAX_PREFIXES} CIDRs"));
    }
    Ok(prefixes)
}

pub fn parse_bool(s: &str) -> Result<bool, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => Ok(false),
        "1" | "true" | "yes" | "on" => Ok(true),
        _ => Err(format!("expected true/false, got {s:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_required() {
        assert!(parse_prefixes("").unwrap_err().contains("CIDR"));
        assert!(parse_prefixes("not-a-cidr").is_err());
        let too_many = (0..17)
            .map(|i| format!("192.0.2.{i}/32"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_prefixes(&too_many).unwrap_err().contains("at most"));
    }

    #[test]
    fn parses_cidrs() {
        let p = parse_prefixes("192.0.2.0/24, 2001:db8::/48").unwrap();
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn bools() {
        assert!(!parse_bool("").unwrap());
        assert!(parse_bool("true").unwrap());
        assert!(parse_bool("maybe").is_err());
    }
}
