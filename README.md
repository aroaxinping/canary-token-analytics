# canary-token-analytics

Threat-intelligence analysis of a deliberately leaked AWS canary token and the 16 real intrusion attempts it recorded.

## What is a canary token?

A canary token is a fake credential that has no real access to anything. Its only purpose is to sound an alarm: the moment someone tries to use it, it sends an alert. Here the token is a fake AWS access key. It grants nothing, but every attempt to authenticate or call an AWS API with it generates an email that captures the source IP, the API action attempted, and a timestamp. In other words, it is a tripwire for credential theft.

## The dataset

The data is **self-generated original data**, not a downloaded or public dataset: a fake-but-real AWS canary token was deliberately published inside a public GitHub repository, and every subsequent attempt to use it was captured as an alert email. Each event corresponds to a real actor — an automated bot or an AWS-side defense — trying to do something with a credential that was already dead.

The first token produced **16 events over roughly one month**. Since expanding to the fleet below, the dataset has grown to **43 events (as of 2026-08-28) and keeps growing** as the tokens keep firing — see [`docs/fleet_placement_analysis.md`](docs/fleet_placement_analysis.md) for the first cross-placement finding.

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

The analysis runs in three stages:

1. **Parse emails** — extract the structured fields (source IP, AWS API action, timestamp) from each raw alert email.
2. **Enrich IPs** — for every source IP, add geolocation, ASN, and infrastructure type (datacenter VPS, cloud provider, residential/mobile proxy, ISP).
3. **Classify intent** — map each observed AWS API call to an attacker-intent phase: validation, reconnaissance, persistence, or resource abuse.

## Key findings

- **AWS auto-quarantined the original leaked key roughly 17 minutes after publication.** From that moment on the credential was inert — every later attempt on it hit a key that had been dead since minute 17.
- **One coordinated actor dominates the traffic.** When the fleet went live, the `terraform.tfvars` key drew a **fan-out of ~15 IPs across ~11 countries all running an identical software build** (same Linux kernel, boto3 version, and retry mode), each taking a different step of the kill-chain. That is the signature of a single operator behind a rotating proxy pool, not many independent attackers — see [`docs/fleet_placement_analysis.md`](docs/fleet_placement_analysis.md).
- **Intent skews toward LLMjacking.** The money-move events cluster on **AWS Bedrock** (`InvokeModel` / `Converse`), i.e. hijacking the account to run AI at the victim's expense — the newer monetization pattern for stolen cloud credentials. Recon and validation still dominate by volume, with an IAM `CreateUser` **persistence** attempt in the tail.
- **A leaked key is hit within minutes.** Across the fleet, fresh placements begin drawing automated traffic almost immediately after exposure — and none of it could have worked, since every request landed on a canary that grants nothing.

## Scope & limitations

- **Small dataset.** 43 events is enough to describe behavior, not to make statistical claims. Treat every observation as descriptive, not inferential.
- **Descriptive, not predictive.** This is descriptive threat-intelligence analysis, not statistical modelling. It characterizes what happened; it does not forecast or generalize to a population.
- **Placement is confounded.** With one repository per placement, the concentration of traffic on `terraform.tfvars` cannot be cleanly attributed to the file type — it is confounded with which specific key reached a shared credential feed. See [`docs/fleet_placement_analysis.md`](docs/fleet_placement_analysis.md).
- **No attribution of people.** Enrichment identifies infrastructure (IPs, ASNs, geography), not the humans behind it. Attributing individuals is out of scope and would require legal process.

## Repository structure

```
canary-token-analytics/
├── src/            # canary_token_analytics package (parsing, enrichment, classification)
├── data/
│   ├── raw/        # source captures + fleet_registry.csv (token -> repo -> placement)
│   └── processed/  # enriched, analysis-ready CSVs (the portfolio deliverable)
├── notebooks/      # exploratory analysis and visualization
├── docs/           # methodology, monetisation primer, event cheat sheet, placement analysis, IP dossiers, OSINT
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
