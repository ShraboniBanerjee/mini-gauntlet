# Mini Gauntlet

A small cloud posture scanner. It reads a snapshot of AWS, Azure and Google Cloud
configuration (`data/inventory.json`), runs ten security checks over every resource,
stores the findings, and shows them in a dashboard.

- **Scanner engine** (Python): a check registry and a concurrent account scanner.
- **REST API** (FastAPI): starts scans in the background and serves findings from SQLite.
- **Dashboard** (React 18 + TypeScript): scans list, scan detail, filters, live updates.
- **Docker Compose** runs both; **GitHub Actions** lints, type-checks, tests, builds both
  images and smoke-tests the running stack.

Latest green CI run for the final commit: **TODO: paste the link to the Actions run here**

## Run it

You need Docker with Compose v2. From the repository root:

```bash
docker compose up --build
```

- Dashboard: http://localhost:3000
- API: http://localhost:8000 (interactive docs at http://localhost:8000/docs)

Click **Run scan**. The scan shows as running and finishes in about 3 seconds. Data is
kept in the `api-data` volume, so scans survive `docker compose down` and rebuilds;
`docker compose down --volumes` deletes them.

### Without Docker

```bash
# API (Python 3.10+), from backend/
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:create_app --factory --reload --port 8000

# Dashboard (Node 20.19+ or 22.12+), from frontend/ in a second terminal
npm ci
npm run dev        # http://localhost:5173, proxies /api to port 8000
```

### Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `INVENTORY_PATH` | `data/inventory.json` in the repo | Snapshot to scan |
| `DATABASE_PATH` | `mini_gauntlet.db` | SQLite file |
| `SCAN_WORKERS` | `4` | Accounts scanned at the same time |
| `MAX_SIMULATED_LATENCY_MS` | `60000` | Cap on one account's `simulated_latency_ms` |
| `CORS_ORIGINS` | `http://localhost:3000,http://localhost:5173` | Origins allowed to call the API directly |
| `LOG_LEVEL` | `INFO` | Python log level |

## Run the tests

```bash
cd backend && pytest                    # 206 tests
ruff check . && ruff format --check .   # lint
mypy                                    # strict type-check

cd frontend && npm test                 # Vitest + React Testing Library
npm run lint && npm run typecheck       # ESLint, tsc --noEmit

./scripts/smoke-test.sh                 # against a running stack (needs curl and jq)
```

The backend suite includes a "golden" test that scans the shipped snapshot and asserts
the status of all 49 findings: 27 PASS, 18 FAIL, 4 CANNOT_SCAN, score 60.0.

## Architecture

```
 browser ──► dashboard (nginx :8080, published as :3000)
               ├─ /          static React build
               └─ /api/*  ──► api (uvicorn :8000)
                                ├─ POST /api/scans ─► background task ─► Scanner
                                │                                          ├─ thread pool, 4 workers
                                │                                          ├─ one account per worker
                                │                                          └─ registry ─► 10 checks
                                └─ SQLite (volume) ◄── findings saved in one transaction
```

### Scanner engine (`backend/app/scanner/`)

- `models.py`: `Status`, `Severity`, `CheckResult`, `Finding`, and `Unevaluable`, the
  exception a check raises when a field can't be evaluated.
- `registry.py`: the `@check(...)` decorator records a check's ID, title, severity,
  provider, collection and resource-ID field. `load_builtin_checks()` imports every module
  in `checks/`, so **adding a check means writing one decorated function in a new or
  existing file there, and nothing else**. `test_registering_a_check_is_all_it_takes_to_run_it`
  proves it.
- `checks/`: one module per service. A check receives one resource and returns PASS or
  FAIL with details, or raises `Unevaluable`.
- `helpers.py`: typed accessors for untrusted fields (`require_bool`, `parse_port`,
  `internet_cidr`, ...) plus `clean()`, which strips control and bidi characters and
  truncates text before it is stored or logged.
- `engine.py`: loads and validates the snapshot, applies the collection rules, and scans
  accounts concurrently with a `ThreadPoolExecutor` limited to `SCAN_WORKERS`. Each
  account first sleeps its `simulated_latency_ms`. Threads fit because the work is
  waiting, as real cloud API calls would be. With 4 workers the snapshot takes about
  3.0 s (the slowest account), not the 8 s the latencies add up to.
- `scoring.py`: `100 * PASS / (PASS + FAIL)`, rounded half-up with `Decimal`, or `None`.

### API (`backend/app/`)

`main.py` is an app factory, so tests build an app with their own database, inventory
and a no-op `sleep`. `service.py` creates and runs scans, `store.py` is the SQLite layer
(a short-lived connection per call, WAL mode), `api.py` holds the routes and `schemas.py`
the Pydantic models.

| Endpoint | Notes |
| --- | --- |
| `GET /api/health` | `{"status": "ok"}` |
| `GET /api/checks` | The catalog, from the registry |
| `POST /api/scans` | Optional `{"account_ids": [...]}`. 202 with the RUNNING scan. 422 for an empty list, unknown IDs or unknown fields |
| `GET /api/scans` | Newest first, with score and counts by status |
| `GET /api/scans/{id}` | Counts by status, FAIL counts by severity, score overall and per account; 404 if unknown |
| `GET /api/scans/{id}/findings` | Filters `status`, `severity`, `provider`, `account_id`, `check_id` (case-insensitive); `page`, `page_size` (max 100) |

Findings are sorted FAIL, CANNOT_SCAN, PASS; then CRITICAL to LOW; then check ID; then
resource ID. Status and severity ranks are stored as integer columns with an index, so
SQLite sorts and paginates without loading everything.

### Dashboard (`frontend/src/`)

- `ScansPage`: every scan with status, start time in the viewer's time zone, duration,
  score and counts, plus **Run scan**. It polls every 1.5 s while any scan is running.
- `ScanPage`: score, counts by status, FAIL counts by severity, a strip with one mark per
  finding, the per-account table, and the findings table with filters and pagination.
  Filters live in the URL, so a filtered view can be bookmarked or shared.
- `usePolledResource`: one hook for loading, polling and retrying. When the API is down
  it keeps the last data on screen, says what's wrong and retries every 5 s.
- Snapshot strings are only ever rendered as React text. ESLint forbids
  `dangerouslySetInnerHTML` and `innerHTML`, a test renders the snapshot's
  `<img onerror=...>` payload and asserts no `<img>` appears, and nginx sends a strict
  Content-Security-Policy as a second line of defence.

### Docker and CI

Each service has a multi-stage Dockerfile with a pinned base image, a non-root user, a
`.dockerignore` and a health check. The API image is `python:3.12.16-slim-trixie` with
only a virtualenv and `app/`; the dashboard is built with Node and served by
`nginx-unprivileged`, which also proxies `/api`, so the browser uses a single origin.
Compose drops all Linux capabilities and sets `no-new-privileges`.

CI runs on every push and pull request: Ruff, mypy and pytest; ESLint, `tsc --noEmit`
and Vitest; then `docker compose build` of both images, `docker compose up --wait`, and
`scripts/smoke-test.sh`, which runs a real scan through the nginx proxy and checks the
results.

## Decisions and assumptions

Where the brief left room, these are the calls I made.

**Rules shared by every check**

- A malformed field only makes a finding CANNOT_SCAN when the verdict depends on it.
  A security group rule open only to `10.0.0.0/8` is a PASS whatever its ports say.
- If one item (a rule, a key, a binding) is unreadable but another one definitely fails,
  the finding is a FAIL, and its details also list what couldn't be evaluated. Without a
  definite failure, one unreadable item makes the finding CANNOT_SCAN, because a PASS
  can't be claimed.
- "Open to the internet" means a source with prefix length 0: `0.0.0.0/0`, `::/0`, and
  Azure's `*`, `Any` and `Internet`. Narrower public ranges are not flagged.
- SSH and RDP are TCP 22 and 3389. UDP rules can't open an SSH or RDP session, so they
  don't fail the check. "All traffic" rules (`-1`, `*`, `all`) do.
- A collection listed in `errors` wins over the same collection in `resources`.
- A resource with no usable ID becomes a CANNOT_SCAN finding with no resource ID.
- Numbers can arrive as numeric strings (`"22"`); booleans are never accepted as numbers.
- A collection that isn't a list (including `null`) is one CANNOT_SCAN finding per check,
  like an error.
- Snapshot-level problems (file missing, invalid JSON, no valid `snapshot_taken_at`,
  `accounts` not a list) fail the whole scan. A malformed account entry is skipped with
  a warning; a negative, non-numeric or huge latency is ignored or capped.

**Per check**

- **AWS-S3-01**: `public_access_block: null` means no configuration was ever set, which
  AWS treats as not blocking, so it is a FAIL. A missing key is CANNOT_SCAN. Account-level
  Block Public Access isn't in the snapshot, so it isn't considered.
- **AWS-IAM-01**: users without console access PASS; their MFA setting isn't read.
- **AWS-IAM-02**: a key fails only if `snapshot_taken_at - created_at` is greater than
  90 days, so a key exactly 90 days old passes. Inactive keys are ignored. Timestamps
  without a time zone are taken as UTC.
- **AZ-NSG-01**: only inbound Allow rules can fail. The snapshot has no rule priorities,
  so an Allow rule counts as effective even if a Deny rule for the same port exists. This
  can over-report; modelling priority is listed under next steps.
- **GCP-VPC-01**: disabled and egress rules pass. Where Google Cloud documents a default
  for an omitted field, it applies: direction defaults to INGRESS, `disabled` to false, a
  TCP entry without `ports` to every port, and an ingress rule with no source to
  `0.0.0.0/0`.
- **GCP-GCS-01**: `allUsers` and `allAuthenticatedUsers` in any role are public.

**API and storage**

- Scans run in FastAPI background tasks in the API process. A scan still RUNNING when the
  API starts was cut off by a restart, so startup marks it FAILED with a reason.
- A scan's findings are written in one transaction with the switch to COMPLETED, so a
  scan is never half-saved.
- `POST /api/scans` checks account IDs against the snapshot at request time. If the
  snapshot can't be read then, the scan is still created and fails with the reason,
  which is what FAILED is for.
- Scan IDs are UUIDs. Times are stored and returned as UTC ISO 8601; the dashboard
  converts them to the viewer's time zone.

## Trade-offs

- **Background tasks instead of a queue.** Simple and enough for one process, but a scan
  dies with the process, and scans can't be spread across machines. Production would use
  a queue and separate workers (see `DEPLOY.md`).
- **SQLite instead of PostgreSQL.** No extra service and the data lives in a volume, but
  it suits one API instance. The SQL is plain enough to port.
- **Threads, not asyncio, for concurrency.** The checks are synchronous and the latency
  stands in for blocking SDK calls such as boto3, so a bounded thread pool is the
  natural fit.
- **Polling, not server-sent events.** 1.5 s polling is simple, survives proxies, and
  stops as soon as nothing is running.

## Unfinished, and what I'd do next

- Model NSG rule priorities and GCP firewall priorities and deny rules, to cut false
  positives.
- Move scans to a queue with separate workers, and the store to PostgreSQL.
- Authentication on the API and dashboard; an API key on `POST /api/scans`.
- Let the dashboard start a scan of selected accounts (the API already supports it).
- Stretch goals not attempted: infrastructure as code, live AWS mode with moto, CIS
  mapping, scan comparison, image scanning and SBOMs in CI, CSV export.
- Pin base images and GitHub Actions by digest and keep them current with Renovate.

## Time spent

<!-- Fill in your real times before submitting. -->

| Part | Time |
| --- | --- |
| Reading the brief, planning, working through the snapshot by hand | _fill in_ |
| Scanner engine and checks | _fill in_ |
| REST API and storage | _fill in_ |
| Dashboard | _fill in_ |
| Tests | _fill in_ |
| Docker and CI | _fill in_ |
| DEPLOY.md and README | _fill in_ |

## Use of AI assistants

<!-- Make this match what you actually did before submitting. -->

I used Claude (Anthropic) as a coding assistant throughout. It drafted most of the
code, tests, Docker and CI configuration and documentation, from the brief and my
direction. I reviewed every file, ran the test suites, the linters and the stack
locally, and made these changes myself: _fill in_.
