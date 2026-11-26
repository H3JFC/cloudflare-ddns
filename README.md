# cloudflare-ddns

A lightweight Cloudflare Dynamic DNS client for Linux. It polls your public IPv4 address and, when it changes, updates one or more existing Cloudflare DNS `A` records. It runs as a hardened systemd service.

## Requirements

- Ubuntu / Debian on **amd64** with systemd (the package depends on `libc6 >= 2.35`; Ubuntu 22.04+ or Debian 12+ is recommended)
- `sudo` access
- A Cloudflare account with a zone (domain) and at least one **existing `A` record** to keep updated
- Outbound HTTPS access to `api.cloudflare.com` and to the IP-check URL (default `https://api.ipify.org`)

## Before you install

The installer asks for these values, so gather them first.

### 1. Create a Cloudflare API token

1. Go to <https://dash.cloudflare.com/profile/api-tokens> and choose **Create Token**.
2. Use **Create Custom Token** with the permission **Zone → DNS → Edit**.
3. Under **Zone Resources**, restrict it to the specific zone you are updating (**Include → Specific zone**).
4. Create the token and copy it. It is only shown once.

### 2. Find your Zone ID and Record IDs

- **Zone ID:** in the Cloudflare dashboard, open your domain and find *Zone ID* in the right-hand sidebar of the **Overview** page.
- **Record IDs:** the dashboard does not display these, so query the API:

```bash
# Replace with your token and zone ID
export CLOUDFLARE_API_TOKEN="your_token"
ZONE_ID="your_zone_id"

curl -s -H "Authorization: Bearer ${CLOUDFLARE_API_TOKEN}" \
  "https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records?type=A" \
  | grep -o '"id":"[^"]*","name":"[^"]*"'
```

(With `jq` installed: `... | jq -r '.result[] | "\(.id)  \(.name)"'`.)

Each record you list in the config must already exist as an `A` record. The daemon only changes its IP content; it does not create records.

## Install from a release

Releases are published at <https://github.com/h3jfc/cloudflare-ddns/releases>. The current release is [v0.1.8](https://github.com/h3jfc/cloudflare-ddns/releases/tag/v0.1.8). Package files are named `cloudflare-ddns_<version>_amd64.deb`.

### 3. Download the package

```bash
VERSION=0.1.8
wget "https://github.com/h3jfc/cloudflare-ddns/releases/download/v${VERSION}/cloudflare-ddns_${VERSION}_amd64.deb"
```

Or with curl:

```bash
curl -fLO "https://github.com/h3jfc/cloudflare-ddns/releases/download/v${VERSION}/cloudflare-ddns_${VERSION}_amd64.deb"
```

You can also download the `.deb` from the release page in your browser and copy it to the server with `scp`.

### 4. Install it

```bash
sudo apt install "./cloudflare-ddns_${VERSION}_amd64.deb"
```

`apt install ./file.deb` is preferred over `dpkg -i` because it resolves dependencies automatically. (`sudo dpkg -i <file>` also works.) Keep the leading `./`; without it `apt` looks for a package by name.

The package installs:

| Path | Purpose |
| --- | --- |
| `/usr/bin/cloudflare-ddns` | The binary |
| `/usr/lib/systemd/system/cloudflare-ddns.service` | The systemd unit |
| `/usr/share/doc/cloudflare-ddns/config.example.toml` | Example configuration |
| `/etc/cloudflare-ddns/config.toml` | Settings: zone, records, polling interval (generated from your answers) |
| `/etc/cloudflare-ddns/cloudflare.env` | Holds the API token (generated from your answers) |

The installer also creates a `cloudflare-ddns` system user and group that the service runs as.

**During installation you will be prompted** for the values below (gathered in steps 1 and 2). The installer writes them to the correct files, then **enables and starts the service automatically**.

| Prompt | Written to |
| --- | --- |
| Cloudflare API token | `CLOUDFLARE_API_TOKEN` in `/etc/cloudflare-ddns/cloudflare.env` |
| Zone ID | `zone_id` in `/etc/cloudflare-ddns/config.toml` |
| DNS record ID | `record_id` in `config.toml` |
| DNS record name | `record_name` in `config.toml` |
| Seconds between IP checks (default `300`) | `interval_seconds` in `config.toml` |

Values may not contain spaces, quotes or `#`. The prompt covers one record; to update more, add further `[[cloudflare.records]]` blocks afterwards (see step 5) and restart.

If the prompts are skipped (non-interactive install, or you leave answers blank), the package installs but the service is **not** enabled or started, and you configure it manually as in step 5. Your answers are never asked again on upgrade.

### Unattended install (optional)

Pre-seed the answers with `debconf-set-selections`, then install non-interactively:

```bash
sudo debconf-set-selections <<EOF
cloudflare-ddns cloudflare-ddns/api_token password YOUR_TOKEN
cloudflare-ddns cloudflare-ddns/zone_id string YOUR_ZONE_ID
cloudflare-ddns cloudflare-ddns/record_id string YOUR_RECORD_ID
cloudflare-ddns cloudflare-ddns/record_name string home.example.com
cloudflare-ddns cloudflare-ddns/interval_seconds string 300
EOF
sudo DEBIAN_FRONTEND=noninteractive apt install -y "./cloudflare-ddns_${VERSION}_amd64.deb"
```

### 5. Manual configuration (optional)

The installer already did this if you answered its prompts. Use this step to add more records, change settings, or configure after skipping the prompts. Edit the settings file:

```bash
sudo nano /etc/cloudflare-ddns/config.toml
```

```toml
[cloudflare]
zone_id = "your_zone_id"

# One [[cloudflare.records]] block per A record to keep updated
[[cloudflare.records]]
record_id = "id_for_home"
record_name = "home.example.com"

[[cloudflare.records]]
record_id = "id_for_vpn"
record_name = "vpn.example.com"

[ddns]
interval_seconds = 300                      # how often to check your public IP
ip_check_url = "https://api.ipify.org"      # must return your public IPv4 as plain text
request_timeout_seconds = 10                # timeout for each HTTP request
```

Then set the API token:

```bash
sudo nano /etc/cloudflare-ddns/cloudflare.env
```

```ini
CLOUDFLARE_API_TOKEN=your_token_here
```

Use no quotes and no spaces around `=`. Keep this file readable only by root and the `cloudflare-ddns` group (the package sets this up; verify with `ls -l /etc/cloudflare-ddns`).

### 6. Enable and start the service (only if not done by the installer)

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cloudflare-ddns
```

`enable` makes it start at boot; `--now` also starts it immediately.

### 7. Verify

```bash
systemctl status cloudflare-ddns
sudo journalctl -u cloudflare-ddns -f
```

A healthy start logs `Cloudflare DDNS daemon started`, followed by each target record and the polling interval. Then check the record in Cloudflare (or with `dig +short home.example.com`) to confirm it matches your public IP.

## Changing configuration later

The service reads `config.toml` and `cloudflare.env` only at startup, so **restart after any change**:

```bash
sudo systemctl restart cloudflare-ddns
sudo journalctl -u cloudflare-ddns -n 50 --no-pager
```

### Environment settings

| Variable | Where | Description |
| --- | --- | --- |
| `CLOUDFLARE_API_TOKEN` | `/etc/cloudflare-ddns/cloudflare.env` | **Required.** Cloudflare API token with Zone DNS Edit. |
| `RUST_LOG` | `Environment=RUST_LOG=info` in the unit file | Log level: `error`, `warn`, `info` (default), `debug`, `trace`. |

To change the log level without editing the packaged unit file (so upgrades don't clobber it), use a systemd drop-in:

```bash
sudo systemctl edit cloudflare-ddns
```

```ini
[Service]
Environment=RUST_LOG=debug
```

Save, then `sudo systemctl restart cloudflare-ddns`.

The binary also accepts an alternate config path as its first argument: `cloudflare-ddns /path/to/config.toml` (default `/etc/cloudflare-ddns/config.toml`).

## Upgrading

Download the new `.deb` and install it over the old one:

```bash
VERSION=<new version>
wget "https://github.com/h3jfc/cloudflare-ddns/releases/download/v${VERSION}/cloudflare-ddns_${VERSION}_amd64.deb"
sudo apt install "./cloudflare-ddns_${VERSION}_amd64.deb"
sudo systemctl restart cloudflare-ddns
```

Your existing files in `/etc/cloudflare-ddns/` are left untouched and you are not prompted again. The installer restarts the service automatically so the new binary is running (the explicit `restart` above is harmless).

## Uninstall

```bash
sudo apt remove cloudflare-ddns      # stops the service, keeps /etc/cloudflare-ddns
sudo apt purge cloudflare-ddns       # also removes config files, including your token
```

## Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| `Fatal startup error: CLOUDFLARE_API_TOKEN is not configured` | `cloudflare.env` is empty or has the wrong format. Fix it and restart. |
| `Fatal startup error` about config or `zone_id` | Placeholder values still in `config.toml`, or a TOML syntax error. |
| Service restarts every 30 seconds | Startup is failing (the unit uses `Restart=always`). Read `journalctl -u cloudflare-ddns -n 50`. |
| `DDNS check failed` with an authentication / permission error | Token lacks **Zone → DNS → Edit**, or is scoped to a different zone. |
| Record not found / wrong type | `record_id` is wrong, or the record is not an `A` record. Re-run the record lookup in step 4. |
| `Permission denied` reading config | Ownership or mode changed. Run `sudo chown root:cloudflare-ddns /etc/cloudflare-ddns/* && sudo chmod 640 /etc/cloudflare-ddns/*`. |

## Building from source

```bash
make test
make build                      # target/release/cloudflare-ddns
./packaging/build-deb.sh        # build/output/cloudflare-ddns_<version>_amd64.deb
```

Releases are built by GitHub Actions when a `v*` tag matching the `Cargo.toml` version is pushed (`make bump-patch`, then `make git-tag`, then `git push origin v<version>`).

## License

MIT
