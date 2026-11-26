use anyhow::{Context, Result, anyhow};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::net::Ipv4Addr;
use std::thread;
use std::time::Duration;
use tracing::{error, info};

const CLOUDFLARE_API: &str = "https://api.cloudflare.com/client/v4";

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
    record_id: String,
    record_name: String,
}

#[derive(Debug, Deserialize)]
struct DdnsConfig {
    interval_seconds: u64,
    ip_check_url: String,
    request_timeout_seconds: u64,
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

    let mut seen_ids = HashSet::new();

    for record in &config.cloudflare.records {
        if record.record_id.trim().is_empty() || record.record_name.trim().is_empty() {
            return Err(anyhow!(
                "Cloudflare record configuration contains empty values"
            ));
        }

        if !seen_ids.insert(record.record_id.as_str()) {
            return Err(anyhow!(
                "Duplicate record_id in config: {}",
                record.record_id
            ));
        }
    }

    if config.ddns.interval_seconds == 0 || config.ddns.request_timeout_seconds == 0 {
        return Err(anyhow!("Intervals and timeouts must be positive"));
    }

    if !config.ddns.ip_check_url.starts_with("https://") {
        return Err(anyhow!("IP discovery URL must use HTTPS"));
    }

    Ok(())
}

fn load_config(path: &str) -> Result<Config> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("Cannot read config: {}", path))?;

    let config: Config = toml::from_str(&contents).context("Invalid TOML configuration")?;

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

fn validate_record(record: &DnsRecord, expected_id: &str, expected_name: &str) -> Result<()> {
    if record.id != expected_id {
        return Err(anyhow!("Cloudflare returned an unexpected record ID"));
    }

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

fn get_public_ip(client: &Client, url: &str) -> Result<Ipv4Addr> {
    let response = client.get(url).send()?.error_for_status()?;

    let body = response.text()?;

    validate_ipv4(&body)
}

/// Fetches every A record in the zone with a single GET request and
/// returns them keyed by record ID.
fn get_dns_records(
    client: &Client,
    token: &str,
    zone_id: &str,
) -> Result<HashMap<String, DnsRecord>> {
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

    let records = data
        .result
        .ok_or_else(|| anyhow!("Cloudflare returned no DNS records"))?;

    Ok(records
        .into_iter()
        .map(|record| (record.id.clone(), record))
        .collect())
}

fn update_dns(
    client: &Client,
    token: &str,
    zone_id: &str,
    record_config: &RecordConfig,
    ip: Ipv4Addr,
) -> Result<()> {
    let url = format!(
        "{}/zones/{}/dns_records/{}",
        CLOUDFLARE_API, zone_id, record_config.record_id
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

    validate_record(
        &updated,
        &record_config.record_id,
        &record_config.record_name,
    )?;

    if updated.content != ip.to_string() {
        return Err(anyhow!("Cloudflare update verification failed"));
    }

    info!(
        "Successfully updated {} to {}",
        record_config.record_name, ip
    );

    Ok(())
}

fn process_record(
    client: &Client,
    token: &str,
    zone_id: &str,
    record_config: &RecordConfig,
    dns_records: &HashMap<String, DnsRecord>,
    public_ip: Ipv4Addr,
) -> Result<()> {
    let record = dns_records.get(&record_config.record_id).ok_or_else(|| {
        anyhow!(
            "A record not found in Cloudflare zone: {} ({})",
            record_config.record_name,
            record_config.record_id
        )
    })?;

    validate_record(record, &record_config.record_id, &record_config.record_name)?;

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

    update_dns(client, token, zone_id, record_config, public_ip)
}

fn check_and_update(client: &Client, config: &Config, token: &str) -> Result<()> {
    // Discover public IP once.
    let public_ip = get_public_ip(client, &config.ddns.ip_check_url)?;

    info!("Detected public IPv4: {}", public_ip);

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
        .user_agent("cloudflare-ddns/1.0.0")
        .build()?;

    info!("Cloudflare DDNS daemon started");
    for record in &config.cloudflare.records {
        info!("Target DNS record: {}", record.record_name);
    }
    info!("Polling interval: {} seconds", config.ddns.interval_seconds);

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

    fn config_with(records: Vec<(&str, &str)>) -> Config {
        Config {
            cloudflare: CloudflareConfig {
                zone_id: "zone123".into(),
                records: records
                    .into_iter()
                    .map(|(id, name)| RecordConfig {
                        record_id: id.into(),
                        record_name: name.into(),
                    })
                    .collect(),
            },
            ddns: DdnsConfig {
                interval_seconds: 300,
                ip_check_url: "https://example.com/ip".into(),
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
        assert!(validate_record(&r, "record123", "home.example.com").is_ok());
    }

    #[test]
    fn rejects_wrong_record_name() {
        let r = record("record123", "other.example.com", "A");
        assert!(validate_record(&r, "record123", "home.example.com").is_err());
    }

    #[test]
    fn rejects_wrong_record_type() {
        let r = record("record123", "home.example.com", "AAAA");
        assert!(validate_record(&r, "record123", "home.example.com").is_err());
    }

    #[test]
    fn accepts_valid_multi_record_config() {
        let config = config_with(vec![("id1", "a.example.com"), ("id2", "b.example.com")]);
        assert!(validate_config(&config).is_ok());
    }

    #[test]
    fn rejects_empty_record_list() {
        let config = config_with(vec![]);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_duplicate_record_ids() {
        let config = config_with(vec![("id1", "a.example.com"), ("id1", "b.example.com")]);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_empty_record_values() {
        let config = config_with(vec![("id1", "  ")]);
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn parses_toml_with_multiple_records() {
        let toml_src = r#"
            [cloudflare]
            zone_id = "zone123"

            [[cloudflare.records]]
            record_id = "id1"
            record_name = "a.example.com"

            [[cloudflare.records]]
            record_id = "id2"
            record_name = "b.example.com"

            [ddns]
            interval_seconds = 300
            ip_check_url = "https://example.com/ip"
            request_timeout_seconds = 10
        "#;

        let config: Config = toml::from_str(toml_src).unwrap();
        assert_eq!(config.cloudflare.records.len(), 2);
        assert!(validate_config(&config).is_ok());
    }
}
