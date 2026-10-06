# Cinnabar Vulnerability Exposure

A self-contained service that helps you answer one simple question:

> **"Which of my software may be vulnerable to known security issues?"**

It keeps its own up-to-date library of security advisories, and you can ask it about the software you run. It gives you a careful, honest answer — it never shouts "you're hacked", it only says "this may be worth a closer look".

---

## What it does, in plain words

1. It downloads the official vulnerability lists from two trusted public sources:
   - **NVD** — the U.S. government's master list of software vulnerabilities (CVEs).
   - **CISA KEV** — the list of vulnerabilities that attackers are actively using right now (the important ones).

2. It stores all of that in its own local database (PostgreSQL), so it works even when the internet or those sources are unavailable.

3. You (or your app) tell it what software you run — for example, "OpenSSH version 9.6p1" — and it tells you which known vulnerabilities *might* apply to that exact version.

It is deliberately **not** tied to any one company, hospital, server, or dashboard. It just knows about software and vulnerabilities. Other systems can plug into it freely.

---

## A note on "may be vulnerable"

The service is careful and honest. A match means:

> *"Your version falls inside the range of versions that a vulnerability affects — you might be affected."*

It does **not** mean "you are definitely hacked". It also cannot tell whether your operating system already shipped a hidden fix (Linux distributions often patch software without changing the version number). Use its answer as a starting point for investigation, not as proof of a break-in.

---

## What you need before you start

- **Docker** installed on your computer or server. That's it.
- Optional but recommended: a free **NVD API key** from <https://nvd.nist.gov/developers/request-an-api-key>. It makes downloading faster. Without it, everything still works, just slower.

---

## Getting started (5 steps)

Open a terminal in this folder, then run these commands one at a time.

### 1. Copy the settings template

```bash
cp .env.example .env
```

### 2. Open the `.env` file and set a database password

Find the line `POSTGRES_PASSWORD=change-me` and replace `change-me` with a password you choose. (You can also add your `NVD_API_KEY` here if you have one.)

### 3. Start the database

```bash
docker compose up -d postgres
```

### 4. Prepare the database

```bash
docker compose run --rm cve-api migrate
```

### 5. Download the vulnerability data

```bash
docker compose run --rm cve-sync sync nvd --full
docker compose run --rm cve-sync sync kev
```

> The first command can take a while — it's downloading a very large public list. Let it finish. You only run it once; after that, the service updates itself automatically.

### 6. Start everything

```bash
docker compose up -d
```

That's it. The service is now running.

---

## Is it working?

```bash
docker compose ps
```

Then check in your browser or with a command:

```bash
curl localhost:8080/health/ready
```

If you see `{"status":"ready"}`, you're good to go.

---

## Asking it about your software

Here's an example. You want to know whether your OpenSSH 9.6p1 might be affected:

```bash
curl -X POST localhost:8080/v1/resolve \
  -H 'Content-Type: application/json' \
  -d '{
    "cpes": ["cpe:/a:openbsd:openssh:9.6p1"],
    "product": "OpenSSH",
    "version": "9.6p1",
    "method": "probed",
    "confidence": 10
  }'
```

It replies with something like:

```json
{
  "status": "ok",
  "matches": [
    {
      "cve_id": "CVE-2024-6387",
      "state": "MATCHED",
      "severity": "HIGH",
      "cvss": 8.1,
      "is_kev": true,
      "version": "9.6p1",
      "match_confidence": "HIGH",
      "reason": "vendor/product matched and version 9.6p1 is inside affected range (>= 9.0 and < 9.7)"
    }
  ],
  "uncertain": []
}
```

How to read it:

- **`matches`** — vulnerabilities that *may* apply to your version.
- **`uncertain`** — cases where it couldn't tell for sure (it prefers to say "not sure" over guessing).
- **`state: MATCHED`** — your version is inside the affected range.
- **`is_kev: true`** — attackers are actively using this one right now, so it deserves priority.
- **`reason`** — a plain explanation of *why* it matched, so you can verify it yourself.

---

## The main things you can do

| What | How |
|------|-----|
| Check if software is affected | `POST /v1/resolve` |
| Check many programs at once | `POST /v1/resolve/batch` |
| Look up one vulnerability | `GET /v1/cves/CVE-2024-6387` |
| Browse/search the vulnerability list | `GET /v1/cves?severity=HIGH` |
| See if the service and its data are healthy | `GET /health/ready` and `GET /v1/status` |
| Check the download status | `GET /v1/status` |

The complete list of commands and examples lives further down in this file under "For developers".

---

## How it updates itself

Once running, the service refreshes its vulnerability list on its own, in the background:

- The NVD list is re-checked every 30 minutes.
- The "actively exploited" (KEV) list is re-checked every 2 hours.

If the internet or the sources are down, no problem — the service keeps answering questions from the data it already has. It simply tries again later.

---

## Backing up

The only thing worth backing up is the database. The vulnerability list can always be re-downloaded.

```bash
docker compose exec -T postgres pg_dump -U cve cve > backup.sql
```

To restore it later:

```bash
docker compose exec -T postgres psql -U cve cve < backup.sql
```

---

## Privacy

This service does **not** need — and should never be given — private information like server names, IP addresses, hospital or customer identities, or internal network details. You only send it software descriptions (name + version). It echoes back whatever *reference label* you attach to your request, so *your* app can match the answer to *your* records.

---

## For developers

### Architecture

Three containers, all from one codebase:

- `cve-api` — answers questions (the API).
- `cve-sync` — downloads and refreshes the vulnerability data in the background.
- `postgres` — stores everything.

It is written in **Go** (a single small, fast program) and uses **PostgreSQL**. The only external code dependency is the PostgreSQL driver; everything else is the Go standard library.

### API reference

- `GET /health` — is the process running
- `GET /health/live` — liveness (always alive if up)
- `GET /health/ready` — readiness (can it reach the database)
- `GET /v1/status` — data freshness and counts (NVD/KEV last sync, CVE count, etc.)
- `GET /v1/cves/{cve_id}` — full detail for one CVE
- `GET /v1/cves` — search/browse (filters: `cve`, `vendor`, `product`, `severity`, `kev`, `modified_since`, `page`, `page_size`)
- `POST /v1/resolve` — resolve one fingerprint
- `POST /v1/resolve/batch` — resolve many at once (each item may carry an opaque `client_ref` that is echoed back)
- `GET /metrics` — Prometheus metrics

Optional authentication: set `CVE_API_KEYS` in `.env` to a comma-separated list of tokens, then send `Authorization: Bearer <token>`.

### Resolver states

| State | Meaning |
|-------|---------|
| `MATCHED` | version inside the affected range — *potentially affected* |
| `NOT_MATCHED` | version outside the affected range |
| `UNCERTAIN` | version could not be reliably compared |
| `INSUFFICIENT_DATA` | not enough information to evaluate |

Confidence is reported as `HIGH`, `MEDIUM`, or `LOW`.

### Configuration

All settings are environment variables — see `.env.example`. Key ones: `DATABASE_URL`, `CVE_API_KEYS`, `NVD_API_KEY`, `NVD_SYNC_INTERVAL`, `KEV_SYNC_INTERVAL`, `CVE_MAX_BATCH_ITEMS`, `CVE_MAX_PAGE_SIZE`, `CVE_LOG_LEVEL`.

### Running the tests

```bash
go test ./...
go vet ./...
go build ./...
```

---

## Where to go next

This is a foundation. Natural additions for the future:

- Support for more sources (package managers, Linux distributions, GitHub advisories)
- SBOM (software bill-of-materials) ingestion
- EPSS scores (how likely a vulnerability is to be exploited)
- Ready-made client libraries so other apps can talk to it easily