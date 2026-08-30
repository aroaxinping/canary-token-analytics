# canary-token-analytics

Threat-intelligence analysis of a fleet of deliberately leaked AWS canary tokens and the real intrusion attempts they recorded (462 events and counting).

## What is a canary token?

A canary token is a fake credential that has no real access to anything. Its only purpose is to sound an alarm: the moment someone tries to use it, it sends an alert. Here the token is a fake AWS access key. It grants nothing, but every attempt to authenticate or call an AWS API with it generates an email that captures the source IP, the API action attempted, and a timestamp. In other words, it is a tripwire for credential theft.

## The dataset

The data is **self-generated original data**, not a downloaded or public dataset: a fake-but-real AWS canary token was deliberately published inside a public GitHub repository, and every subsequent attempt to use it was captured as an alert email. Each event corresponds to a real actor — an automated bot or an AWS-side defense — trying to do something with a credential that was already dead.

The first token produced **16 events over roughly one month**. Since expanding to the fleet below, the dataset has grown to **462 events (as of 2026-08-30) and keeps growing** as the tokens keep firing — see [`docs/fleet_placement_analysis.md`](docs/fleet_placement_analysis.md) for the first cross-placement finding.

## Data collection: the honeypot fleet

The first month's events came from a **single** token. To grow the dataset into something that can eventually support statistics — and to compare how the *placement* of a leaked key affects how fast it is found — the token is now one of a small **fleet** of canary tokens, each planted in a different public repository and a different kind of file:

| Token | Repository | Placement |
|---|---|---|
| 1 | [social-metrics-vault](https://github.com/aroaxinping/social-metrics-vault) | `.env` |
| 2 | [homelab-s3-sync](https://github.com/aroaxinping/homelab-s3-sync) | `.env` |
| 3 | [cloud-usage-tracker](https://github.com/aroaxinping/cloud-usage-tracker) | `config.ini` |
| 4 | [sensor-data-lake](https://github.com/aroaxinping/sensor-data-lake) | `settings.yaml` |
| 5 | [infra-heartbeat](https://github.com/aroaxinping/infra-heartbeat) | `terraform.tfvars` |

Each token is unique, so every alert is attributable back to a specific repo and placement (see [`data/raw/fleet_registry.csv`](data/raw/fleet_registry.csv)). Those repositories are intentionally thin instruments of the experiment, each carrying a clear note that the credential is a canary token; this repository is where their data is collected and analyzed.

## Why a leaked key is a target: how it gets monetised

An AWS access key is effectively **a payment method wired to an infinite supermarket of compute**. Anyone holding it can order Amazon services *as the victim's account* — and the bill lands on the victim. "Free for the attacker" always means the same thing: someone else pays. That is why bots start testing a key within minutes of it hitting a public repo, probing for these four businesses:

| AWS service | What it rents | How it's monetised | Events seen in this data |
|---|---|---|---|
| **Bedrock** | AI models | Free/resold AI on the victim's bill (**LLMjacking**) | `InvokeModel`, `Converse`, `ListFoundationModels` |
| **SES** | Email delivery | Phishing that inherits Amazon's inbox reputation | `GetSendQuota` |
| **S3** | Storage | Steal and sell the victim's data | `ListBuckets` |
| **IAM** | Users & permissions | Create a back door that survives key revocation | `CreateUser` |

See [`docs/how_a_stolen_key_is_monetised.md`](docs/how_a_stolen_key_is_monetised.md) for the full walkthrough, and [`docs/event_cheatsheet.md`](docs/event_cheatsheet.md) for what every observed API call does.

## Pipeline

The dataset is kept current end to end, from inbox to analysis-ready CSV, in one command (and, if you want, automatically on a schedule):

1. **Ingest alerts** — pull every canarytoken alert from Gmail over the Gmail API (read-only), parse each email body into a structured event (source IP, AWS API action, timestamp, token/placement), and merge it into the raw dataset. Parsing and de-duplication live in the tested [`ingest`](src/canary_token_analytics/ingest.py) module; the Gmail fetch is [`scripts/fetch_gmail.py`](scripts/fetch_gmail.py).
2. **Enrich IPs** — for every source IP, add geolocation, ASN, and infrastructure type (datacenter VPS, cloud provider, residential/mobile proxy, ISP), proxy/hosting/mobile flags (ip-api), and a GreyNoise mass-scanning signal.
3. **Classify intent** — map each observed AWS API call to an attacker-intent phase (validation, reconnaissance, persistence, resource abuse) using a fixed, documented taxonomy.

```bash
uv run --extra gmail python scripts/fetch_gmail.py   # pull + parse + dedup new alerts
uv run python scripts/build_dataset.py               # enrich + classify -> data/processed/
```

### Automated ingestion & scheduling

The whole fetch-and-rebuild loop runs unattended. A macOS **launchd** job ([`scripts/run_ingest.sh`](scripts/run_ingest.sh) + [`deploy/com.aroa.canary-ingest.plist`](deploy/com.aroa.canary-ingest.plist)) executes the Gmail fetch and dataset rebuild **every 6 hours**, so the dataset stays current with no manual step. It leaves new data in the working tree for review — it never commits or pushes. One-time Gmail OAuth setup is in [`docs/INGESTION_SETUP.md`](docs/INGESTION_SETUP.md); the scheduler in [`docs/SCHEDULER_SETUP.md`](docs/SCHEDULER_SETUP.md).

### Two OSINT tiers

Enrichment is layered so the base pipeline stays fast while a deeper pass adds per-IP intelligence:

- **Base tier** (in the pipeline above): geolocation, ASN/org, infra type, ip-api proxy/hosting/mobile flags, and GreyNoise — written to [`data/processed/ip_intel.csv`](data/processed/ip_intel.csv).
- **Deep tier** ([`enrich_deep.py`](src/canary_token_analytics/enrich_deep.py) via [`scripts/build_deep_osint.py`](scripts/build_deep_osint.py)): a passive per-IP dossier — Shodan InternetDB (open ports, tags, CVEs), `whois` (netblock, org, country, abuse contact), and reverse DNS — written to [`data/processed/ip_intel_deep.csv`](data/processed/ip_intel_deep.csv). All lookups query third-party databases *about* the IP; nothing ever connects to attacker infrastructure. Attribution stops at infrastructure. See [`docs/osint_deep.md`](docs/osint_deep.md).

## Key findings

- **AWS auto-quarantined the original leaked key roughly 17 minutes after publication.** From that moment on the credential was inert — every later attempt on it hit a key that had been dead since minute 17.
- **One coordinated actor dominates the traffic.** The `terraform.tfvars` key drew a **fan-out of 53 IPs across 23 countries all running an identical software build** (same Linux kernel, boto3 version, and retry mode), each taking a different step of the kill-chain. **48 of 53** of those IPs resolve to hosting/proxy networks (M247, HostRoyale, ServerMania, Leaseweb…) — the signature of a single operator behind a rotating proxy pool, not many independent attackers. See [`docs/fleet_placement_analysis.md`](docs/fleet_placement_analysis.md).
- **Intent skews toward LLMjacking, with a privilege-escalation attempt.** The money-move events cluster on **AWS Bedrock** (`InvokeModel` / `Converse`) — hijacking the account to run AI at the victim's expense. Separately, a hands-on operator on the `config.ini` key attempted **`PutUserPolicy`** (granting itself durable permissions), and one IP (`197.57.31.248`) worked **two** different placements — actors handle multiple keys.
- **A leaked key is hit within minutes.** Across the fleet, fresh placements begin drawing automated traffic almost immediately after exposure — and none of it could have worked, since every request landed on a canary that grants nothing.

## Experiment: does placement matter? (A/B)

The fleet finding above — that "infrastructure-flavored" keys (e.g. `terraform.tfvars`) draw faster, deeper attacks — is **suggestive but confounded**: with one repository per placement, a file type is entangled with which specific key happened to reach a shared credential-abuse feed. A correlation, not a cause.

To settle it, the [`experiment/`](experiment/) directory specifies a **randomized, matched-block field experiment**: 50 thin public repos, organized as **10 matched blocks × 5 conditions**, where the credential-bearing file (`.env` → `config.ini` → `terraform.tfvars` → CI deploy workflow, plus a fake-key negative control) is assigned **at random** within each block, and launched in two temporally separated waves. Random assignment de-confounds placement from feed luck; blocking strips out the huge day-to-day noise in scanning intensity. Outcomes — time-to-first-hit (survival), hit volume, proxy-pool appearance, and kill-chain depth — are analysed with survival, count, and ordinal mixed models against an *a priori* monotone "infra-ness" gradient.

The full causal design, statistical plan, and honest power/limitations discussion are in [`experiment/DESIGN.md`](experiment/DESIGN.md); the deployment runbook in [`experiment/ROLLOUT.md`](experiment/ROLLOUT.md).

## Scope & limitations

- **Small dataset.** 462 events is enough to describe behavior, not to make statistical claims. Treat every observation as descriptive, not inferential.
- **Descriptive, not predictive.** This is descriptive threat-intelligence analysis, not statistical modelling. It characterizes what happened; it does not forecast or generalize to a population.
- **Placement is confounded.** With one repository per placement, the concentration of traffic on `terraform.tfvars` cannot be cleanly attributed to the file type — it is confounded with which specific key reached a shared credential feed. This is exactly what the [randomized A/B experiment](#experiment-does-placement-matter-ab) is designed to de-confound. See [`docs/fleet_placement_analysis.md`](docs/fleet_placement_analysis.md).
- **No attribution of people.** Enrichment identifies infrastructure (IPs, ASNs, geography), not the humans behind it. Attributing individuals is out of scope and would require legal process.

## Repository structure

```
canary-token-analytics/
├── src/canary_token_analytics/
│   ├── ingest.py       # parse alert emails -> events + dedup/merge (tested)
│   ├── enrich.py       # geo / ASN / infra type / proxy flags / GreyNoise
│   ├── enrich_deep.py  # deep tier: Shodan InternetDB + whois + reverse DNS
│   ├── taxonomy.py     # AWS API call -> attacker-intent phase
│   └── pipeline.py     # orchestrates raw -> enriched CSVs
├── data/
│   ├── raw/            # source captures + fleet_registry.csv (token -> repo -> placement)
│   └── processed/      # enriched, analysis-ready CSVs incl. ip_intel_deep.csv (the deliverable)
├── experiment/         # randomized A/B placement experiment: DESIGN.md, ROLLOUT.md, block plan
├── scripts/            # fetch_gmail.py, build_dataset.py, build_deep_osint.py, run_ingest.sh
├── deploy/             # launchd plist for scheduled ingestion
├── notebooks/          # exploratory analysis and visualization
├── docs/               # methodology, monetisation primer, event cheat sheet, placement analysis, ingestion/scheduler setup, OSINT
└── tests/              # unit + data-quality tests
```

See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for how the data was collected, enriched, and graded for confidence.

## How to run

This project uses [uv](https://docs.astral.sh/uv/).

```bash
# install dependencies into a local environment
uv sync

# pull new canarytoken alerts from Gmail, parse + dedup them (read-only)
uv run --extra gmail python scripts/fetch_gmail.py

# build the enriched dataset from the raw events (enrich + classify)
uv run python scripts/build_dataset.py

# optional: deep per-IP OSINT dossiers (Shodan InternetDB + whois + rDNS)
uv run python scripts/build_deep_osint.py
```

`build_dataset.py` alone rebuilds the analysis from the raw events already in the repo — no Gmail setup needed. To pull fresh alerts, do the one-time Gmail OAuth setup ([`docs/INGESTION_SETUP.md`](docs/INGESTION_SETUP.md)); to run the fetch+rebuild automatically every 6 hours, install the launchd job ([`docs/SCHEDULER_SETUP.md`](docs/SCHEDULER_SETUP.md)).
