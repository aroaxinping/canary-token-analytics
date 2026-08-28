# canary-token-analytics

Threat-intelligence analysis of a deliberately leaked AWS canary token and the 16 real intrusion attempts it recorded.

## What is a canary token?

A canary token is a fake credential that has no real access to anything. Its only purpose is to sound an alarm: the moment someone tries to use it, it sends an alert. Here the token is a fake AWS access key. It grants nothing, but every attempt to authenticate or call an AWS API with it generates an email that captures the source IP, the API action attempted, and a timestamp. In other words, it is a tripwire for credential theft.

## The dataset

The data is **self-generated original data**, not a downloaded or public dataset: a fake-but-real AWS canary token was deliberately published inside a public GitHub repository, and every subsequent attempt to use it was captured as an alert email. Each event corresponds to a real actor — an automated bot or an AWS-side defense — trying to do something with a credential that was already dead.

The first token produced **16 events over roughly one month**. Since expanding to the fleet below, the dataset has grown to **36 events (as of 2026-08-28) and keeps growing** as the tokens keep firing — see [`docs/fleet_placement_analysis.md`](docs/fleet_placement_analysis.md) for the first cross-placement finding.

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

## Pipeline

The analysis runs in three stages:

1. **Parse emails** — extract the structured fields (source IP, AWS API action, timestamp) from each raw alert email.
2. **Enrich IPs** — for every source IP, add geolocation, ASN, and infrastructure type (datacenter VPS, cloud provider, residential/mobile proxy, ISP).
3. **Classify intent** — map each observed AWS API call to an attacker-intent phase: validation, reconnaissance, persistence, or resource abuse.

## Key findings

- **AWS auto-quarantined the leaked key roughly 17 minutes after publication.** From that moment on the credential was inert — every later attempt hit a key that had been dead since minute 17.
- **Attacker infrastructure escalated over the month.** The traffic moved from a camouflaged datacenter VPS (Frankfurt), to free cloud infrastructure (GCP), to US residential and mobile proxies, and finally to Indonesian ISPs — a progression from obvious datacenter origins toward harder-to-attribute residential ranges.
- **Observed intents spanned several attacker phases.** They ranged from simple key validation, to reconnaissance, to an **IAM `CreateUser` persistence attempt**, to an **`InvokeModel` LLMjacking attempt against AWS Bedrock** (hijacking the account's model access for the attacker's own inference).
- **None of it could have worked.** Every intent above was attempted against a credential AWS had already killed within the first 17 minutes.

## Scope & limitations

- **Small dataset.** 16 events is enough to describe behavior, not to make statistical claims. Treat every observation as descriptive, not inferential.
- **Descriptive, not predictive.** This is descriptive threat-intelligence analysis, not statistical modelling. It characterizes what happened; it does not forecast or generalize to a population.
- **No attribution of people.** Enrichment identifies infrastructure (IPs, ASNs, geography), not the humans behind it. Attributing individuals is out of scope and would require legal process.

## Repository structure

```
canary-token-analytics/
├── src/            # canary_token_analytics package (parsing, enrichment, classification)
├── data/
│   ├── raw/        # source captures + fleet_registry.csv (token -> repo -> placement)
│   └── processed/  # enriched, analysis-ready CSVs (the portfolio deliverable)
├── notebooks/      # exploratory analysis and visualization
├── docs/           # methodology, placement analysis, per-IP dossiers, OSINT tooling, AWS ref
├── scripts/        # entry points, including build_dataset.py
└── tests/          # unit + data-quality tests
```

See [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) for how the data was collected, enriched, and graded for confidence.

## How to run

This project uses [uv](https://docs.astral.sh/uv/).

```bash
# install dependencies into a local environment
uv sync

# build the enriched dataset from the raw events
uv run python scripts/build_dataset.py
```
