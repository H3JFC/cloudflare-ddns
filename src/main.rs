use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::io::Read;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;
use tracing::{error, info, warn};

const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";

/// Maximum accepted size of an IP-check response body. A valid IPv4 address
/// with a trailing newline is at most 16 bytes; anything larger is rejected
/// so a malicious server cannot make us buffer an unbounded response.
const MAX_IP_RESPONSE_BYTES: usize = 64;

const DEFAULT_IP_CHECK_URL_1: &str = "https://api.ipify.org";
const DEFAULT_IP_CHECK_URL_2: &str = "https://checkip.amazonaws.com";
const DEFAULT_IP_CHECK_URL_3: &str = "https://ifconfig.me/ip";

/// Lowest allowed polling interval. Prevents hammering the IP-check services
/// and the Cloudflare API.
const MIN_INTERVAL_SECONDS: u64 = 60;

/// Number of sources that must report the same IP before DNS is updated.
const REQUIRED_AGREEMENT: usize = 2;

#[derive(Debug, Deserialize)]
struct Config {
    cloudflare: CloudflareConfig,
    ddns: DdnsConfig,
}

#[derive(Debug, Deserialize)]
struct CloudflareConfig {
    zone_id: String,
    records: Vec<RecordConfig>,
}

#[derive(Debug, Deserialize)]
struct RecordConfig {
    record_name: String,
}

#[derive(Debug, Deserialize)]
struct DdnsConfig {
    interval_seconds: u64,
    /// Deprecated single-source setting. If present it replaces `ip_check_url_1`.
    #[serde(default)]
    ip_check_url: Option<String>,
    #[serde(default = "default_ip_check_url_1")]
    ip_check_url_1: String,
    #[serde(default = "default_ip_check_url_2")]
    ip_check_url_2: String,
    #[serde(default = "default_ip_check_url_3")]
    ip_check_url_3: String,
    request_timeout_seconds: u64,
}

impl DdnsConfig {
    /// IP sources in the order they are queried.
    fn ip_check_urls(&self) -> [&str; 3] {
        [
            &self.ip_check_url_1,
            &self.ip_check_url_2,
            &self.ip_check_url_3,
        ]
    }
}

fn default_ip_check_url_1() -> String {
    DEFAULT_IP_CHECK_URL_1.to_string()
}

fn default_ip_check_url_2() -> String {
    DEFAULT_IP_CHECK_URL_2.to_string()
}

fn default_ip_check_url_3() -> String {
    DEFAULT_IP_CHECK_URL_3.to_string()
}

#[derive(Debug, Deserialize)]
struct ApiError {
    #[allow(dead_code)]
    code: Option<i64>,
    message: String,
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    errors: Vec<ApiError>,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct DnsRecord {
    id: String,
    name: String,
    #[serde(rename = "type")]
    record_type: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct UpdateRequest {
    content: String,
}

fn validate_config(config: &Config) -> Result<()> {
    if config.cloudflare.zone_id.trim().is_empty() {
        return Err(anyhow!("Cloudflare zone_id is empty"));
    }

    if config.cloudflare.records.is_empty() {
        return Err(anyhow!("At least one DNS record must be configured"));
    }

    let mut seen_names = HashSet::new();

    for record in &config.cloudflare.records {
        if record.record_name.trim().is_empty() {
            return Err(anyhow!("Cloudflare record_name must not be empty"));
        }

        if !seen_names.insert(record.record_name.trim().to_ascii_lowercase()) {
            return Err(anyhow!(
                "Duplicate record_name in config: {}",
                record.record_name
            ));
        }
    }

    if config.ddns.interval_seconds < MIN_INTERVAL_SECONDS {
        return Err(anyhow!(
            "interval_seconds must be at least {} (got {})",
            MIN_INTERVAL_SECONDS,
            config.ddns.interval_seconds
        ));
    }

    if config.ddns.request_timeout_seconds == 0 {
        return Err(anyhow!("request_timeout_seconds must be positive"));
    }

    let urls = config.ddns.ip_check_urls();

    for (i, url) in urls.iter().enumerate() {
        if !url.starts_with("https://") {
            return Err(anyhow!("IP discovery URL must use HTTPS: {}", url));
        }

        if urls[..i]
            .iter()
            .any(|other| other.eq_ignore_ascii_case(url))
        {
            return Err(anyhow!(
                "ip_check_url_1, ip_check_url_2 and ip_check_url_3 must be different services"
            ));
        }
    }

    Ok(())
}

fn load_config(path: &str) -> Result<Config> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("Cannot read config: {}", path))?;

    let mut config: Config = toml::from_str(&contents).context("Invalid TOML configuration")?;

    if let Some(legacy) = config.ddns.ip_check_url.take() {
        warn!(
            "ip_check_url is deprecated; using it as ip_check_url_1. \
             Replace it with ip_check_url_1 and ip_check_url_2 in {}",
            path
        );
        config.ddns.ip_check_url_1 = legacy;
    }

    validate_config(&config)?;

    Ok(config)
}

fn validate_ipv4(value: &str) -> Result<Ipv4Addr> {
    let ip: Ipv4Addr = value.trim().parse().context("Invalid IPv4 address")?;

    if ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
    {
        return Err(anyhow!("IP address is not a usable public IPv4 address"));
    }

    Ok(ip)
}

fn validate_record(record: &DnsRecord, expected_name: &str) -> Result<()> {
    if !record.name.eq_ignore_ascii_case(expected_name) {
        return Err(anyhow!(
            "DNS record name mismatch: expected {}, received {}",
            expected_name,
            record.name
        ));
    }

    if record.record_type != "A" {
        return Err(anyhow!(
            "Expected DNS record type A, received {}",
            record.record_type
        ));
    }

    Ok(())
}

/// Reads at most `MAX_IP_RESPONSE_BYTES` from `reader` and parses it as a
/// public IPv4 address. Errors (rather than truncating) if more data arrives.
fn read_ip_bounded<R: Read>(reader: R) -> Result<Ipv4Addr> {
    let mut buf = Vec::new();
    reader
        .take(MAX_IP_RESPONSE_BYTES as u64 + 1)
        .read_to_end(&mut buf)
        .context("Failed to read IP response")?;

    if buf.len() > MAX_IP_RESPONSE_BYTES {
        return Err(anyhow!(
            "IP response exceeded {} bytes",
            MAX_IP_RESPONSE_BYTES
        ));
    }

    let body = std::str::from_utf8(&buf).context("IP response was not valid UTF-8")?;

    validate_ipv4(body)
}

fn fetch_ip(client: &Client, url: &str) -> Result<Ipv4Addr> {
    let response = client.get(url).send()?.error_for_status()?;

    read_ip_bounded(response).with_context(|| format!("IP check failed for {}", url))
}

/// Queries the sources in order and returns as soon as `REQUIRED_AGREEMENT`
/// of them report the same IP, so remaining sources are not contacted.
/// A source that fails is logged and skipped. If no IP reaches the required
/// agreement, an error is returned and nothing should be updated.
fn resolve_with<F>(urls: &[&str], mut fetch: F) -> Result<Ipv4Addr>
where
    F: FnMut(&str) -> Result<Ipv4Addr>,
{
    let mut answers: Vec<(&str, Ipv4Addr)> = Vec::new();
    let mut failures = 0;

    for url in urls {
        match fetch(url) {
            Ok(ip) => {
                answers.push((url, ip));

                if answers.iter().filter(|(_, a)| *a == ip).count() >= REQUIRED_AGREEMENT {
                    return Ok(ip);
                }
            }
            Err(err) => {
                failures += 1;
                warn!("{:#}", err);
            }
        }
    }

    let reported: Vec<String> = answers
        .iter()
        .map(|(url, ip)| format!("{} -> {}", url, ip))
        .collect();

    Err(anyhow!(
        "No {} IP sources agreed ({} failed; answers: [{}]); not updating DNS",
        REQUIRED_AGREEMENT,
        failures,
        reported.join(", ")
    ))
}

fn resolve_public_ip(client: &Client, urls: &[&str]) -> Result<Ipv4Addr> {
    resolve_with(urls, |url| fetch_ip(client, url))
}

/// Fetches every A record in the zone with a single GET request.
fn get_dns_records(client: &Client, token: &str, zone_id: &str) -> Result<Vec<DnsRecord>> {
    // per_page is raised well above the default of 100 so that the whole
    // zone fits in one response.
    let url = format!(
        "{}/zones/{}/dns_records?type=A&per_page=5000",
        CLOUDFLARE_API, zone_id
    );

    let response = client
        .get(url)
        .bearer_auth(token)
        .send()?
        .error_for_status()?;

    let data: ApiResponse<Vec<DnsRecord>> = response.json()?;

    if !data.success {
        let messages: Vec<&str> = data.errors.iter().map(|e| e.message.as_str()).collect();
        return Err(anyhow!("Cloudflare API error: {}", messages.join("; ")));
    }

    data.result
        .ok_or_else(|| anyhow!("Cloudflare returned no DNS records"))
}

/// Finds the single A record with the given name. Names are matched
/// case-insensitively. Errors if there is no such record, or more than one
/// (e.g. round-robin A records), since the right one to update is ambiguous.
fn find_record<'a>(records: &'a [DnsRecord], name: &str) -> Result<&'a DnsRecord> {
    let mut matches = records
        .iter()
        .filter(|r| r.record_type == "A" && r.name.eq_ignore_ascii_case(name.trim()));

    let first = matches
        .next()
        .ok_or_else(|| anyhow!("No A record named {} found in the Cloudflare zone", name))?;

    if matches.next().is_some() {
        return Err(anyhow!(
            "Multiple A records named {} exist; refusing to guess which one to update",
            name
        ));
    }

    Ok(first)
}

fn update_dns(
    client: &Client,
    token: &str,
    zone_id: &str,
    record: &DnsRecord,
    ip: Ipv4Addr,
) -> Result<()> {
    let url = format!(
        "{}/zones/{}/dns_records/{}",
        CLOUDFLARE_API, zone_id, record.id
    );

    // PATCH changes only the content field.
    // Existing proxy and TTL settings are preserved.
    let payload = UpdateRequest {
        content: ip.to_string(),
    };

    let response = client
        .patch(url)
        .bearer_auth(token)
        .json(&payload)
        .send()?
        .error_for_status()?;

    let data: ApiResponse<DnsRecord> = response.json()?;

    if !data.success {
        let messages: Vec<&str> = data.errors.iter().map(|e| e.message.as_str()).collect();
        return Err(anyhow!(
            "Cloudflare rejected update: {}",
            messages.join("; ")
        ));
    }

    let updated = data
        .result
        .ok_or_else(|| anyhow!("Cloudflare returned no updated record"))?;

    if updated.id != record.id {
        return Err(anyhow!("Cloudflare returned an unexpected record ID"));
    }

    validate_record(&updated, &record.name)?;

    if updated.content != ip.to_string() {
        return Err(anyhow!("Cloudflare update verification failed"));
    }

    info!("Successfully updated {} to {}", record.name, ip);

    Ok(())
}

fn process_record(
    client: &Client,
    token: &str,
    zone_id: &str,
    record_config: &RecordConfig,
    dns_records: &[DnsRecord],
    public_ip: Ipv4Addr,
) -> Result<()> {
    let record = find_record(dns_records, &record_config.record_name)?;

    validate_record(record, &record_config.record_name)?;

    let dns_ip = validate_ipv4(&record.content)?;

    if public_ip == dns_ip {
        info!(
            "{} is already up to date ({})",
            record_config.record_name, public_ip
        );

        return Ok(());
    }

    info!(
        "IP change detected for {}: {} -> {}",
        record_config.record_name, dns_ip, public_ip
    );

    update_dns(client, token, zone_id, record, public_ip)
}

fn check_and_update(client: &Client, config: &Config, token: &str) -> Result<()> {
    // Discover public IP once.
    let public_ip = resolve_public_ip(client, &config.ddns.ip_check_urls())?;

    info!("Detected public IPv4: {} (sources agree)", public_ip);

    // Retrieve all A records with a single GET request.
    let dns_records = get_dns_records(client, token, &config.cloudflare.zone_id)?;

    let mut failures = Vec::new();

    // Process only explicitly configured records.
    for record_config in &config.cloudflare.records {
        // One failure shouldn't prevent other records being processed.
        if let Err(err) = process_record(
            client,
            token,
            &config.cloudflare.zone_id,
            record_config,
            &dns_records,
            public_ip,
        ) {
            error!("Failed to process {}: {:#}", record_config.record_name, err);
            failures.push(record_config.record_name.as_str());
        }
    }

    if !failures.is_empty() {
        return Err(anyhow!(
            "Failed to process {} DNS record(s): {}",
            failures.len(),
            failures.join(", ")
        ));
    }

    Ok(())
}

fn run() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "/etc/cloudflare-ddns/config.toml".to_string());

    let config = load_config(&config_path)?;

    let token =
        env::var("CLOUDFLARE_API_TOKEN").context("CLOUDFLARE_API_TOKEN is not configured")?;

    if token.trim().is_empty() {
        return Err(anyhow!("Cloudflare API token is empty"));
    }

    let client = Client::builder()
        .timeout(Duration::from_secs(config.ddns.request_timeout_seconds))
        .user_agent(concat!("cloudflare-ddns/", env!("CARGO_PKG_VERSION")))
        .build()?;

    info!("Cloudflare DDNS daemon started");
    for record in &config.cloudflare.records {
        info!("Target DNS record: {}", record.record_name);
    }
    info!("Polling interval: {} seconds", config.ddns.interval_seconds);
    info!(
        "IP sources (any {} must agree): {}",
        REQUIRED_AGREEMENT,
        config.ddns.ip_check_urls().join(", ")
    );

    loop {
        if let Err(err) = check_and_update(&client, &config, &token) {
            error!("DDNS check failed: {:#}", err);
        }

        thread::sleep(Duration::from_secs(config.ddns.interval_seconds));
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    if let Err(err) = run() {
        error!("Fatal startup error: {:#}", err);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, name: &str, record_type: &str) -> DnsRecord {
        DnsRecord {
            id: id.into(),
            name: name.into(),
            record_type: record_type.into(),
            content: "8.8.8.8".into(),
        }
    }

    fn config_with(records: Vec<&str>) -> Config {
        Config {
            cloudflare: CloudflareConfig {
                zone_id: "zone123".into(),
                records: records
                    .into_iter()
                    .map(|name| RecordConfig {
                        record_name: name.into(),
                    })
                    .collect(),
            },
            ddns: DdnsConfig {
                interval_seconds: 300,
                ip_check_url: None,
                ip_check_url_1: "https://example.com/ip".into(),
                ip_check_url_2: "https://example.org/ip".into(),
                ip_check_url_3: "https://example.net/ip".into(),
                request_timeout_seconds: 10,
            },
        }
    }

    #[test]
    fn accepts_public_ipv4() {
        assert!(validate_ipv4("8.8.8.8").is_ok());
    }

    #[test]
    fn rejects_private_ipv4() {
        assert!(validate_ipv4("192.168.1.1").is_err());
    }

    #[test]
    fn rejects_invalid_ipv4() {
        assert!(validate_ipv4("not-an-ip").is_err());
    }

    #[test]
    fn accepts_correct_record() {
        let r = record("record123", "home.example.com", "A");
        assert!(validate_record(&r, "home.example.com").is_ok());
    }

    #[test]
    fn rejects_wrong_record_name() {
        let r = record("record123", "other.example.com", "A");
        assert!(validate_record(&r, "home.example.com").is_err());
    }

    #[test]
    fn rejects_wrong_record_type() {
        let r = record("record123", "home.example.com", "AAAA");
        assert!(validate_record(&r, "home.example.com").is_err());
    }

    #[test]
    fn accepts_valid_multi_record_config() {
        let config = config_with(vec!["a.example.com", "b.example.com"]);
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn rejects_empty_record_list() {
        let config = config_with(vec![]);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_duplicate_record_names() {
        let config = config_with(vec!["a.example.com", "A.Example.com"]);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn find_record_matches_by_name_case_insensitively() {
        let records = vec![
            record("id_a", "a.example.com", "A"),
            record("id_b", "b.example.com", "A"),
        ];
        assert_eq!(find_record(&records, "B.Example.com").unwrap().id, "id_b");
    }

    #[test]
    fn find_record_errors_when_missing() {
        let records = vec![record("id_a", "a.example.com", "A")];
        assert!(find_record(&records, "missing.example.com").is_err());
    }

    #[test]
    fn find_record_errors_on_duplicate_names() {
        let records = vec![
            record("id_1", "rr.example.com", "A"),
            record("id_2", "rr.example.com", "A"),
        ];
        let err = find_record(&records, "rr.example.com").unwrap_err();
        assert!(err.to_string().contains("Multiple A records"));
    }

    #[test]
    fn find_record_ignores_non_a_records() {
        let records = vec![record("id_1", "a.example.com", "AAAA")];
        assert!(find_record(&records, "a.example.com").is_err());
    }

    #[test]
    fn legacy_record_id_in_config_is_ignored() {
        let toml_src = r#"
            [cloudflare]
            zone_id = "zone123"

            [[cloudflare.records]]
            record_id = "old_id"
            record_name = "a.example.com"

            [ddns]
            interval_seconds = 300
            request_timeout_seconds = 10
        "#;

        let config: Config = toml::from_str(toml_src).unwrap();
        assert_eq!(config.cloudflare.records[0].record_name, "a.example.com");
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn rejects_empty_record_values() {
        let config = config_with(vec!["  "]);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn parses_toml_with_multiple_records() {
        let toml_src = r#"
            [cloudflare]
            zone_id = "zone123"

            [[cloudflare.records]]
            record_name = "a.example.com"

            [[cloudflare.records]]
            record_name = "b.example.com"

            [ddns]
            interval_seconds = 300
            ip_check_url_1 = "https://example.com/ip"
            ip_check_url_2 = "https://example.org/ip"
            ip_check_url_3 = "https://example.net/ip"
            request_timeout_seconds = 10
        "#;

        let config: Config = toml::from_str(toml_src).unwrap();
        assert_eq!(config.cloudflare.records.len(), 2);
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn ip_urls_default_when_absent() {
        let toml_src = r#"
            [cloudflare]
            zone_id = "zone123"

            [[cloudflare.records]]
            record_name = "a.example.com"

            [ddns]
            interval_seconds = 300
            request_timeout_seconds = 10
        "#;

        let config: Config = toml::from_str(toml_src).unwrap();
        assert_eq!(config.ddns.ip_check_url_1, DEFAULT_IP_CHECK_URL_1);
        assert_eq!(config.ddns.ip_check_url_2, DEFAULT_IP_CHECK_URL_2);
        assert_eq!(config.ddns.ip_check_url_3, DEFAULT_IP_CHECK_URL_3);
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn legacy_ip_check_url_parses() {
        let toml_src = r#"
            [cloudflare]
            zone_id = "zone123"

            [[cloudflare.records]]
            record_name = "a.example.com"

            [ddns]
            interval_seconds = 300
            ip_check_url = "https://example.com/ip"
            request_timeout_seconds = 10
        "#;

        let config: Config = toml::from_str(toml_src).unwrap();
        assert_eq!(
            config.ddns.ip_check_url.as_deref(),
            Some("https://example.com/ip")
        );
    }

    #[test]
    fn rejects_interval_below_minimum() {
        let mut config = config_with(vec!["a.example.com"]);
        config.ddns.interval_seconds = MIN_INTERVAL_SECONDS - 1;
        assert!(validate_config(&config).is_err());
        config.ddns.interval_seconds = 0;
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn accepts_minimum_interval() {
        let mut config = config_with(vec!["a.example.com"]);
        config.ddns.interval_seconds = MIN_INTERVAL_SECONDS;
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn rejects_non_https_ip_url() {
        let mut config = config_with(vec!["a.example.com"]);
        config.ddns.ip_check_url_2 = "http://example.org/ip".into();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_identical_ip_urls() {
        let mut config = config_with(vec!["a.example.com"]);
        config.ddns.ip_check_url_2 = config.ddns.ip_check_url_1.clone();
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_identical_third_ip_url() {
        let mut config = config_with(vec!["a.example.com"]);
        config.ddns.ip_check_url_3 = config.ddns.ip_check_url_2.clone();
        assert!(validate_config(&config).is_err());
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// Runs `resolve_with` over three fake sources, returning the result and
    /// how many sources were actually contacted.
    fn run_sources(answers: Vec<Result<Ipv4Addr>>) -> (Result<Ipv4Addr>, usize) {
        let urls = ["a", "b", "c"];
        let mut answers = answers.into_iter();
        let mut calls = 0;
        let result = resolve_with(&urls, |_| {
            calls += 1;
            answers.next().unwrap()
        });
        (result, calls)
    }

    #[test]
    fn exits_early_when_first_two_agree() {
        let (result, calls) = run_sources(vec![
            Ok(ip("8.8.8.8")),
            Ok(ip("8.8.8.8")),
            Ok(ip("1.1.1.1")),
        ]);
        assert_eq!(result.unwrap(), ip("8.8.8.8"));
        assert_eq!(calls, 2, "third source must not be contacted");
    }

    #[test]
    fn third_breaks_tie_with_first() {
        let (result, calls) = run_sources(vec![
            Ok(ip("8.8.8.8")),
            Ok(ip("1.1.1.1")),
            Ok(ip("8.8.8.8")),
        ]);
        assert_eq!(result.unwrap(), ip("8.8.8.8"));
        assert_eq!(calls, 3);
    }

    #[test]
    fn third_breaks_tie_with_second() {
        let (result, _) = run_sources(vec![
            Ok(ip("8.8.8.8")),
            Ok(ip("1.1.1.1")),
            Ok(ip("1.1.1.1")),
        ]);
        assert_eq!(result.unwrap(), ip("1.1.1.1"));
    }

    #[test]
    fn all_different_is_an_error() {
        let (result, _) = run_sources(vec![
            Ok(ip("8.8.8.8")),
            Ok(ip("1.1.1.1")),
            Ok(ip("9.9.9.9")),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn one_failed_source_is_tolerated() {
        let (result, _) = run_sources(vec![
            Err(anyhow!("down")),
            Ok(ip("8.8.8.8")),
            Ok(ip("8.8.8.8")),
        ]);
        assert_eq!(result.unwrap(), ip("8.8.8.8"));
    }

    #[test]
    fn two_failed_sources_is_an_error() {
        let (result, _) = run_sources(vec![
            Err(anyhow!("down")),
            Err(anyhow!("down")),
            Ok(ip("8.8.8.8")),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn bounded_reader_accepts_ip_with_newline() {
        assert_eq!(
            read_ip_bounded("8.8.8.8\n".as_bytes()).unwrap(),
            "8.8.8.8".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn bounded_reader_accepts_exactly_limit() {
        // "8.8.8.8" padded with whitespace to exactly the limit.
        let body = format!("8.8.8.8{}", " ".repeat(MAX_IP_RESPONSE_BYTES - 7));
        assert_eq!(body.len(), MAX_IP_RESPONSE_BYTES);
        assert!(read_ip_bounded(body.as_bytes()).is_ok());
    }

    #[test]
    fn bounded_reader_rejects_over_limit() {
        let body = format!("8.8.8.8{}", " ".repeat(MAX_IP_RESPONSE_BYTES - 6));
        assert_eq!(body.len(), MAX_IP_RESPONSE_BYTES + 1);
        assert!(read_ip_bounded(body.as_bytes()).is_err());
    }

    #[test]
    fn bounded_reader_rejects_non_utf8() {
        assert!(read_ip_bounded(&[0xff, 0xfe, 0xfd][..]).is_err());
    }
}
