# Why the fleet traffic concentrates on one placement

On 2026-08-28 the fleet recorded 27 events in a single morning. They are not
spread evenly across the five tokens — they pile onto one:

| Placement | Token | Events | Distinct IPs | Countries |
|---|---|---:|---:|---:|
| `terraform.tfvars` | 5 | 20 | 17 | 12 |
| `settings.yaml` | 4 | 6 | 1 | 1 |
| `.env` | 1 | 1 | 1 | 1 |

The obvious reading — *"attackers prefer `terraform.tfvars`"* — is **not
supported by this data**, and the reason why is the interesting part.

## Two very different signatures

The traffic to `terraform.tfvars` and to `settings.yaml` are behaviourally
opposite.

**`terraform.tfvars` — a fan-out / shared-list signature.** Sixteen of its 20
events carry an *identical* software fingerprint: kernel
`linux#6.12.43+deb13-amd64`, `boto3 1.43.80`, `retry-mode legacy` — the same
Debian 13 build. Those sixteen events come from **fifteen different IPs in
eleven countries**, each firing roughly once, over the course of two hours, and
each performing a *different* step of the kill-chain:

```
GetCallerIdentity ×5   (redundant validation)
ListUserPolicies ×3    (permission enumeration)
ListFoundationModels ×2 (Bedrock recon)
Converse / InvokeModel ×3 (Bedrock abuse — LLMjacking)
ListSecrets            (hunt for more credentials)
ListBuckets            (hunt for S3 data stores)
GetSendQuota           (SES abuse prep)
```

Fifteen "different" hosts running one very specific kernel build, each taking
one step, is not fifteen independent attackers. It is **one operator behind a
rotating proxy / botnet pool** (or one tool shared across a crew), spreading the
calls over many egress IPs to dodge per-IP rate-limiting and attribution. The
remaining events on this key are 2–3 unrelated actors on their own builds
(Debian bullseye + `boto3 1.43.81`; Windows + `boto3 1.42.65`). Corroborating
this, 8 of the 9 fan-out IPs checked resolve to hosting/proxy providers
(ip-api `proxy`/`hosting` flags): Datalix, code200 UAB, ServerMania, Creanova,
HostRoyale, HostPapa — a commercial proxy pool, not independent residential
hosts.

**`settings.yaml` — a single-operator signature.** All six of its events come
from **one** IP (`197.57.31.248`, Telecom Egypt) working a checklist in
sequence: `GetCallerIdentity → ListRoles → ListFunctions → GetSendQuota …`.
One host, methodical, no fan-out.

## What actually drives the concentration

The concentration is best explained by **propagation, not file type**: the
`terraform.tfvars` key has landed in a *widely-replayed shared credential feed*
(an aggregated dump / scanner database that many actors — and one proxy pool —
are replaying), while the `settings.yaml` key has so far only been found by a
single scanner. The fan-out cluster is the direct evidence of that shared feed.

A tempting secondary hypothesis is that `terraform.tfvars` *itself* attracts
more attention — an Infrastructure-as-Code file implies real, broadly-permissioned
cloud infra, so a harvester might prioritise promoting its key to the shared
list. That is plausible, but **this dataset cannot confirm it**: with exactly
one repository per placement, "placement" is perfectly confounded with "which
specific key happened to reach the shared feed." Separating the two would need
several repositories per file type, randomised — a proper A/B design, which is
[future work](NEXT_STEPS.md).

## The honest takeaway

- The strong, defensible finding is the **fan-out cluster**: one actor,
  one Debian-13 build, nine countries, one key, a coordinated LLMjacking-oriented
  kill-chain. That stands on the fingerprint evidence alone.
- The **placement preference** is *not* established. The apparent
  `terraform.tfvars` bias is confounded with credential-feed propagation and is
  reported as an open question, not a conclusion.
