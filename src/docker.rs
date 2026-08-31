use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const DOCKER_SOCK: &str = "/var/run/docker.sock";
const CGROUP_FS: &str = "/sys/fs/cgroup";
const LABEL: &str = "egresso=true";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container {
    pub name: String,
    pub cgroup: PathBuf,
}

pub fn available() -> bool {
    Path::new(DOCKER_SOCK).exists()
}

pub fn containers() -> Result<Vec<Container>, String> {
    let mut out: Vec<Container> = Vec::new();
    for name in list_labeled()? {
        match cgroup(&name) {
            Ok(path) if is_root_cgroup(&path) => {
                eprintln!("{name}: root cgroup, skipping");
            }
            Ok(path) => {
                if !out.iter().any(|c| c.cgroup == path) {
                    out.push(Container { name, cgroup: path });
                }
            }
            Err(e) => eprintln!("{e}"),
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

fn list_labeled() -> Result<Vec<String>, String> {
    let filters = format!(r#"{{"label":["{LABEL}"]}}"#);
    let path = format!("/containers/json?filters={}", encode_query(&filters));
    Ok(parse_list_names(&docker_get(&path)?))
}

fn cgroup(name: &str) -> Result<PathBuf, String> {
    let inspect = inspect(name)?;
    if inspect.pid <= 0 {
        return Err(format!("{name} is not running"));
    }
    cgroup_from_inspect(&inspect)
}

struct Inspect {
    id: String,
    pid: i64,
}

fn inspect(name: &str) -> Result<Inspect, String> {
    let path = format!("/containers/{}/json", encode_query(name));
    let body = docker_get(&path).map_err(|e| {
        if e.contains("HTTP 404") {
            format!("no such container {name}")
        } else {
            e
        }
    })?;
    parse_inspect(&body).ok_or_else(|| "docker API: missing Id/Pid".into())
}

fn cgroup_from_inspect(inspect: &Inspect) -> Result<PathBuf, String> {
    let id = inspect.id.trim_start_matches("sha256:");
    for p in [
        PathBuf::from(format!("{CGROUP_FS}/system.slice/docker-{id}.scope")),
        PathBuf::from(format!("{CGROUP_FS}/docker/{id}")),
    ] {
        if p.exists() {
            return Ok(p);
        }
    }
    if inspect.pid > 0 {
        if let Ok(raw) = std::fs::read_to_string(format!("/proc/{}/cgroup", inspect.pid)) {
            if let Some(path) = path_from_proc_cgroup(&raw).filter(|p| p.exists()) {
                return Ok(path);
            }
        }
    }
    Err(format!(
        "no cgroup for docker-{id}.scope (is /sys/fs/cgroup mounted?)"
    ))
}

fn path_from_proc_cgroup(raw: &str) -> Option<PathBuf> {
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("0::") {
            let rel = rest.trim().trim_start_matches('/');
            return Some(Path::new(CGROUP_FS).join(rel));
        }
    }
    None
}

fn is_root_cgroup(p: &Path) -> bool {
    p.as_os_str().to_string_lossy().trim_end_matches('/') == CGROUP_FS
}

fn parse_list_names(json: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = json;
    while let Some(i) = rest.find("\"Names\":") {
        rest = &rest[i + 8..];
        let Some(start) = rest.find('[') else { break };
        let Some(end) = rest[start..].find(']') else {
            break;
        };
        let arr = &rest[start + 1..start + end];
        if let Some(name) = arr.split(',').next() {
            let n = name.trim().trim_matches('"').trim_start_matches('/');
            if !n.is_empty() && !out.iter().any(|x| x == n) {
                out.push(n.to_string());
            }
        }
        rest = &rest[start + end + 1..];
    }
    out
}

fn parse_inspect(json: &str) -> Option<Inspect> {
    let id = json_str(json, "Id")?
        .trim_start_matches("sha256:")
        .to_string();
    if id.is_empty() {
        return None;
    }
    let state = json.find("\"State\"")?;
    let pid = json_i64(&json[state..], "Pid")?;
    Some(Inspect { id, pid })
}

fn docker_get(path: &str) -> Result<String, String> {
    let mut stream =
        UnixStream::connect(DOCKER_SOCK).map_err(|e| format!("connect {DOCKER_SOCK}: {e}"))?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    write!(stream, "GET {path} HTTP/1.0\r\nHost: docker\r\n\r\n")
        .map_err(|e| format!("write docker.sock: {e}"))?;
    let (status, body) = read_http(&mut stream)?;
    if !(200..300).contains(&status) {
        return Err(format!("docker API HTTP {status}"));
    }
    Ok(body)
}

fn json_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":\"");
    let start = json.find(&pat)? + pat.len();
    json[start..].split('"').next()
}

fn json_i64(json: &str, key: &str) -> Option<i64> {
    let pat = format!("\"{key}\":");
    let start = json.find(&pat)? + pat.len();
    json[start..]
        .trim_start()
        .split(|c: char| !c.is_ascii_digit() && c != '-')
        .next()?
        .parse()
        .ok()
}

fn encode_query(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn read_http(stream: &mut UnixStream) -> Result<(u16, String), String> {
    let mut r = BufReader::new(stream);
    let mut status_line = String::new();
    r.read_line(&mut status_line)
        .map_err(|e| format!("docker.sock: {e}"))?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("docker.sock: bad status {status_line:?}"))?;
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        r.read_line(&mut line)
            .map_err(|e| format!("docker.sock: {e}"))?;
        if line.is_empty() || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = rest.trim().parse().ok();
        }
    }
    let mut body = Vec::new();
    if let Some(n) = content_length {
        body.resize(n.min(8 * 1024 * 1024), 0);
        r.read_exact(&mut body)
            .map_err(|e| format!("docker.sock body: {e}"))?;
    } else {
        r.take(8 * 1024 * 1024)
            .read_to_end(&mut body)
            .map_err(|e| format!("docker.sock body: {e}"))?;
    }
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_docker_inspect_json() {
        let json = r#"{"Id":"34930211daa3abc","Created":"x","State":{"Status":"running","Running":true,"Pid":4321}}"#;
        let i = parse_inspect(json).unwrap();
        assert_eq!(i.id, "34930211daa3abc");
        assert_eq!(i.pid, 4321);
    }

    #[test]
    fn proc_cgroup_line() {
        let p = path_from_proc_cgroup("0::/system.slice/docker-abc.scope\n").unwrap();
        assert_eq!(
            p,
            PathBuf::from("/sys/fs/cgroup/system.slice/docker-abc.scope")
        );
    }

    #[test]
    fn root_cgroup() {
        assert!(is_root_cgroup(Path::new("/sys/fs/cgroup")));
        assert!(is_root_cgroup(Path::new("/sys/fs/cgroup/")));
        assert!(!is_root_cgroup(Path::new(
            "/sys/fs/cgroup/system.slice/docker-abc.scope"
        )));
    }

    #[test]
    fn list_names() {
        let json = r#"[{"Names":["/searxng-1"]},{"Names":["/searxng-2","/alias"]}]"#;
        assert_eq!(parse_list_names(json), vec!["searxng-1", "searxng-2"]);
    }

    #[test]
    fn query_encodes_label_filter() {
        let filters = format!(r#"{{"label":["{LABEL}"]}}"#);
        assert_eq!(
            encode_query(&filters),
            "%7B%22label%22%3A%5B%22egresso%3Dtrue%22%5D%7D"
        );
    }
}
