# 🛡️ Threat Watch — Live Threat Intel Dashboard

A self-monitoring dashboard that watches a list of IP addresses, periodically
re-checks them against **VirusTotal**, **AbuseIPDB**, and **Shodan**, and
emails you the moment an IP's risk level goes up. Deployable for free on
Render. A one-off/bulk **CLI** is included too, sharing the exact same
checking logic as the live app.

## What it does

- **Watchlist** — add or remove IPs from a web dashboard, no login required
- **Auto re-check** — a background scheduler re-checks every watched IP on a
  fixed interval (default every 2 hours, configurable)
- **Live dashboard** — current risk level, per-source breakdown, and last
  checked time for every IP, auto-refreshing every 15 seconds
- **Email alerts** — an email fires the moment an IP's risk *increases*
  (never on decrease, and never repeatedly for the same level)
- **CLI mode** — check a single IP or a file full of IPs from the terminal,
  output as a table, JSON, or CSV

## Project structure

```
threat-intel-dashboard/
├── app.py                     ← Flask app factory + entry point
├── checker/                   ← core checking logic (shared by CLI + web app)
│   ├── cli.py                 ← command-line entry point
│   ├── engine.py               ← build_sources() / check_ip() — the shared core
│   ├── validator.py           ← IP validation (single + bulk)
│   ├── reporter.py            ← CLI output formatting (table/JSON/CSV)
│   └── sources/                ← one module per threat feed
│       ├── base.py            ← abstract ThreatSource + safe_check()
│       ├── virustotal.py
│       ├── abuseipdb.py
│       └── shodan.py
├── dashboard/                  ← the live app
│   ├── state.py                ← in-memory watchlist + last-known results
│   ├── scheduler.py            ← APScheduler background re-check job
│   ├── alerts.py                ← Gmail SMTP alerting
│   └── routes.py                ← JSON API + dashboard page
├── templates/dashboard.html
├── static/style.css            ← red/white SOC-console theme
├── tests/
├── notebooks/                   ← original exploratory notebook (demo only)
├── requirements.txt
├── render.yaml                  ← Render deploy config
├── Procfile
└── .env.example
```

## Quick start (local)

```bash
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# edit .env and add at least one API key

python app.py
# → http://127.0.0.1:5000
```

Without any API keys set, the app still runs — every source just reports
`UNKNOWN`, which is useful for checking the UI without burning API quota.

## CLI usage

```bash
python -m checker.cli --ip 8.8.8.8
python -m checker.cli --file ips.txt --output json
python -m checker.cli --file ips.txt --output csv --outfile report.csv
```

## Deploying to Render

Your GitHub repo currently only has the original notebook — none of this
has been pushed yet. To get it live:

**1. Add this project to your repo**

```bash
cd path/to/your/local/clone/of/threat-intel-ip-checker
# copy all the files from this package in here (this README, app.py,
# checker/, dashboard/, templates/, static/, tests/, requirements.txt,
# render.yaml, Procfile, .env.example, .gitignore)

git add -A
git commit -m "Restructure into a package and add a live dashboard app"
git push
```

Your existing `Threat_Intelligence_IP_Checker.ipynb` isn't part of this
package (this environment can't read its contents — GitHub blocks
automated reads of raw notebook content). Keep it wherever you like, e.g.
move it into `notebooks/`; the live app doesn't depend on it at all.

**2. Create a Render account** — [render.com](https://render.com), free, no
card required.

**3. New Web Service**

- Render dashboard → **New** → **Web Service**
- Connect your GitHub account, select this repo
- Render detects `render.yaml` automatically — confirm:

  | Field | Value |
  |---|---|
  | Runtime | Python |
  | Build command | `pip install -r requirements.txt` |
  | Start command | `gunicorn app:app --workers 1 --threads 4 --timeout 60` |
  | Instance type | Free |

**4. Add environment variables** (Render → your service → **Environment**)

| Variable | Required | Notes |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | at least one of these three | from virustotal.com |
| `ABUSEIPDB_API_KEY` | | from abuseipdb.com |
| `SHODAN_API_KEY` | | from shodan.io |
| `GMAIL_ADDRESS` | for email alerts | the Gmail account sending alerts |
| `GMAIL_APP_PASSWORD` | for email alerts | 16-char app password, not your real password |
| `ALERT_EMAIL_TO` | for email alerts | where alerts should land |
| `CHECK_INTERVAL_HOURS` | optional | default `2` |
| `ENABLE_SCHEDULER` | optional | default `true` |

⚠️ Add these in Render's UI — never commit real keys to the repo.

**5. Deploy** — click **Create Web Service**. ~2 minutes later it's live at
`https://<your-service-name>.onrender.com`.

### Free tier spin-down

Render's free tier sleeps after 15 minutes with no traffic — the scheduler
pauses too while asleep. Two options:

- **Free:** point a pinger like [UptimeRobot](https://uptimerobot.com) at
  `https://<your-app>.onrender.com/healthz` every 10 minutes to keep it warm.
- **Paid:** Render's $7/mo Starter instance never sleeps.

## Design tradeoffs, on purpose

- **In-memory state, no database.** The watchlist and last-check results
  live in process memory (`dashboard/state.py`), not a database. That's a
  deliberate choice for zero-setup free-tier hosting — it means the
  watchlist resets on restart/redeploy. If that becomes a problem, swap
  `state.py` for a SQLite-backed version; every other module only calls
  `add_ip` / `remove_ip` / `set_result` / `snapshot`, so nothing else needs
  to change.
- **`--workers 1` in gunicorn.** Because state is in-memory, multiple
  worker *processes* would each keep a separate watchlist. One worker with
  multiple *threads* keeps a single shared state while still handling
  concurrent requests.
- **No authentication on the watchlist.** Anyone with the URL can add or
  remove IPs. Fine for a personal tool behind a not-widely-shared URL; add
  a password check in `dashboard/routes.py` if you ever need to lock it
  down.

## Running tests

```bash
pip install -r requirements.txt
pytest -v
```

Tests use `unittest.mock` for every source — no real API calls or network
access are needed to run the suite.

## Adding a new threat feed

1. Create `checker/sources/yourprovider.py`, subclassing `ThreatSource`
   from `checker/sources/base.py`.
2. Implement `check(self, ip)` (call the API, return raw JSON) and
   `risk_level(self, raw_result)` (translate the raw response into
   `"LOW"` / `"MEDIUM"` / `"HIGH"` / `"UNKNOWN"`).
3. Add it to the list in `checker/engine.py::build_sources()`.

That's it — the CLI, the dashboard, the scheduler, and alerting all pick it
up automatically, since they all go through `checker.engine`.
