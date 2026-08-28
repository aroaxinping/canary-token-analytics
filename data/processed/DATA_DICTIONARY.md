# Data Dictionary — processed canary-token dataset

Enriched from `data/raw/canary_alerts_raw.csv` (16 real canary-token
security events). Geo/ASN/org values come from live `ipinfo.io` lookups;
GreyNoise columns come from the GreyNoise community API. Fields that could
not be resolved are left empty — never guessed.

## `alerts_enriched.csv` — one row per event (16 rows)

| Column | Description |
| --- | --- |
| `seq` | Original event sequence number (1–16), chronological. |
| `datetime_utc` | Event timestamp in UTC (ISO 8601). |
| `date_utc` | Event date in UTC (YYYY-MM-DD). |
| `time_utc` | Event time in UTC (HH:MM). |
| `source_ip` | Source IP of the request. `AWS Internal` or blank for AWS's own detections. |
| `event_name` | AWS API action / alert name that fired the canary. |
| `user_agent` | Raw boto3/botocore user-agent string (empty for AWS-internal alerts). |
| `alert_type` | Canary alert category: `ip_triggered`, `aws_internal`, or `safetynet`. |
| `token_id` | Which canary token in the fleet fired this event (see `data/raw/fleet_registry.csv`). |
| `placement` | The kind of file the leaked key was planted in (`.env`, `config.ini`, `settings.yaml`, `terraform.tfvars`). |
| `channel` | How the alert was captured (`email`). |
| `city` | City of the source IP (ipinfo.io). Empty for non-attacker sources. |
| `region` | Region/state of the source IP (ipinfo.io). |
| `country` | ISO country code of the source IP (ipinfo.io). |
| `asn` | Autonomous System Number of the source IP (e.g. `AS7018`). |
| `org` | Organization / network owner of the source IP. |
| `infra_type` | Infrastructure class: `cloud`, `datacenter VPS`, `residential/mobile`, `residential/ISP`. |
| `ua_os` | Operating system parsed from the user agent (e.g. `windows#10`, `linux#5.15.0-46-generic`). |
| `ua_python` | Python version parsed from the user agent. |
| `ua_boto3` | Boto3 version parsed from the user agent. |
| `ua_retry_mode` | Botocore retry mode: `legacy`, `standard`, or `adaptive`. |
| `tool_signature` | Named attacker tool appended to the UA (`DeepAWSAnalyzer/Pro`, `iam_masscek/2.0`), else empty. |
| `intent_phase` | Attack-lifecycle phase (see taxonomy): `validation`, `reconnaissance`, `abuse-prep`, `persistence`, `resource-abuse`, `defense`. |
| `intent_description` | Human-readable explanation of the operator's intent for that event. |

## `ip_intel.csv` — one row per unique attacker IP (9 rows)

| Column | Description |
| --- | --- |
| `source_ip` | Unique attacker IP address. |
| `city` | City (ipinfo.io). |
| `region` | Region/state (ipinfo.io). |
| `country` | ISO country code (ipinfo.io). |
| `asn` | Autonomous System Number. |
| `org` | Organization / network owner. |
| `infra_type` | Infrastructure class (see above). |
| `gn_noise` | GreyNoise community: whether the IP is seen scanning the internet. Empty when the IP is not in GreyNoise's dataset. |
| `gn_riot` | GreyNoise community: whether the IP belongs to a common business service (RIOT). |
| `gn_classification` | GreyNoise community classification (`benign`, `malicious`, `unknown`). |
| `gn_name` | GreyNoise community actor/name label, when known. |

### Notes on this run

- AWS-internal and safetynet events (seq 1, 2, 7) have no source IP and are
  AWS's own fraud/quarantine detections, not attacker infrastructure — they
  are not looked up.
- GreyNoise community returned 404 (IP not observed) for all nine attacker
  IPs, so every `gn_*` field is empty. This is a genuine absence of signal.
- `182.4.101.162` resolves to PT. Telekomunikasi Selular (Telkomsel), an
  Indonesian **mobile** carrier; classified `residential/mobile`. The
  project's expectation table listed it as `residential/ISP` — the live
  lookup indicates a mobile network operator.
