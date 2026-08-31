use ipnet::IpNet;

const PREFIXES: &str = "EGRESSO_PREFIXES";
const HOST_FALLBACK: &str = "EGRESSO_HOST_FALLBACK";

pub const MAX_PREFIXES: usize = 16;

#[derive(Clone, Debug)]
pub struct Config {
    pub prefixes: Vec<IpNet>,
    pub host_fallback: bool,
}

impl Config {
    pub fn load() -> Result<Self, String> {
        Self::parse(&env(PREFIXES), &env(HOST_FALLBACK))
    }

    fn parse(prefixes: &str, host_fallback: &str) -> Result<Self, String> {
        Ok(Self {
            prefixes: parse_prefixes(prefixes)?,
            host_fallback: parse_bool(HOST_FALLBACK, host_fallback)?,
        })
    }
}

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_default().trim().to_string()
}

fn parse_prefixes(raw: &str) -> Result<Vec<IpNet>, String> {
    let mut prefixes = Vec::new();
    for part in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let net: IpNet = part
            .parse()
            .map_err(|e| format!("invalid CIDR {part:?}: {e}"))?;
        prefixes.push(net.trunc());
    }
    if prefixes.is_empty() {
        return Err(format!("{PREFIXES} is required"));
    }
    if prefixes.len() > MAX_PREFIXES {
        return Err(format!("{PREFIXES} supports at most {MAX_PREFIXES} CIDRs"));
    }
    Ok(prefixes)
}

fn parse_bool(name: &str, s: &str) -> Result<bool, String> {
    match s.to_ascii_lowercase().as_str() {
        "" | "0" | "false" | "no" | "off" => Ok(false),
        "1" | "true" | "yes" | "on" => Ok(true),
        _ => Err(format!("invalid {name}: expected true/false, got {s:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_required() {
        assert!(Config::parse("", "").unwrap_err().contains(PREFIXES));
        assert!(Config::parse("not-a-cidr", "").is_err());
        let too_many = (0..17)
            .map(|i| format!("192.0.2.{i}/32"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(Config::parse(&too_many, "")
            .unwrap_err()
            .contains("at most"));
    }

    #[test]
    fn parses_cidrs() {
        let c = Config::parse("192.0.2.0/24, 2001:db8::/48", "").unwrap();
        assert_eq!(c.prefixes.len(), 2);
        assert!(!c.host_fallback);
        let c = Config::parse("192.0.2.0/24", "true").unwrap();
        assert!(c.host_fallback);
    }

    #[test]
    fn bools() {
        assert!(!parse_bool("x", "").unwrap());
        assert!(parse_bool("x", "true").unwrap());
        assert!(parse_bool("x", "maybe").is_err());
    }
}
