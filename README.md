<h1 align="center"> Cyberthreat Visualizer (Basic Prototype)</h1>

<p align="center">
  <strong>Real-time 3D cyber threat intelligence dashboard powered by multi-source OSINT APIs and AI classification</strong>
</p>

<p align="center">
  <img alt="Node.js" src="https://img.shields.io/badge/Node.js-18%2B-339933?logo=nodedotjs&logoColor=white">
  <img alt="React" src="https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black">
  <img alt="Vite" src="https://img.shields.io/badge/Vite-5-646CFF?logo=vite&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-blue">
</p>

---

##  Description

Cyberthreat Visualizer is a full-stack SOC (Security Operations Center) dashboard that aggregates live threat intelligence from multiple OSINT sources, AbuseIPDB, AlienVault OTX, Shodan, and IPInfo and renders the data on an interactive 3D globe. Incoming threat events are automatically classified into attack categories (DDoS, Malware, Port Scan) using a rule-based scoring engine augmented by a Gemini AI or OpenAI layer. The dashboard surface includes real-time arc animations on the globe, a threat feed panel, analyst-grade detail cards, and an AI-powered threat report generator.
<img width="1531" height="991" alt="image" src="https://github.com/user-attachments/assets/dbb72b1f-0c8b-4806-9cf7-6e51f49b2138" />



---

## 🛠 Tech Stack

| Layer | Technology |
|---|---|
| Frontend framework | React 18 + Vite 5 |
| 3D globe | Globe.gl + Three.js |
| Styling | Tailwind CSS v4 |
| Charts | Recharts |
| Backend | Node.js + Express |
| Threat intel APIs | AbuseIPDB, AlienVault OTX, Shodan, IPInfo |
| AI classification | Google Gemini AI / OpenAI (configurable) |
| HTTP | node-fetch |
| Environment | dotenv |

---

##  Prerequisites

- **Node.js** `>= 18.x` ([download](https://nodejs.org/))
- **npm** `>= 9.x` (bundled with Node.js)
- API keys for at least one threat intelligence provider (see [Environment Variables](#-environment-variables) below)

---

##  Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/cyberthreat-visualizer.git
cd cyberthreat-visualizer

# 2. Install frontend dependencies
npm install

# 3. Install backend dependencies
cd server && npm install && cd ..

# 4. Create your environment file
cp server/.env.example server/.env

# 5. Open server/.env and fill in your API keys
#    (see Environment Variables section below)
```

---

##  Running Locally

The frontend and backend are separate processes and must run **concurrently** in two terminal windows.

**Terminal 1 — Frontend (Vite dev server, port 5173):**
```bash
npm run dev
```

**Terminal 2 — Backend (Express API server, port 5000):**
```bash
node server/index.js
```

Then open [http://localhost:5173](http://localhost:5173) in your browser.

> **Note:** The backend must be running before the frontend can show live data. Without it the dashboard shows an "offline" state with a retry button and keeps retrying with backoff. **Simulation** mode (historical WannaCry and Mirai replays) works without the backend and is toggled manually in the header.
>
> The Vite dev and preview servers proxy `/api` to `http://localhost:5000`. To host the API elsewhere, set `VITE_API_BASE` (for example `https://api.example.com/api`) at build time.

---

##  Environment Variables

Copy `server/.env.example` to `server/.env` and populate the values below. The `.env` file is **never committed** to version control.

| Variable | Required | Description | Where to get it |
|---|---|---|---|
| `PORT` | No | Port the Express server listens on (default: `5000`) | — |
| `ABUSEIPDB_API_KEY` | Recommended | IP reputation lookups via AbuseIPDB | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| `IPINFO_API_KEY` | Recommended | IP geolocation and ASN data | [ipinfo.io/account/token](https://ipinfo.io/account/token) |
| `OTX_API_KEY` | Optional | AlienVault OTX threat pulses (works in public mode without key) | [otx.alienvault.com](https://otx.alienvault.com/api) |
| `SHODAN_API_KEY` | Optional | Exposed service and banner data | [account.shodan.io](https://account.shodan.io) |
| `AI_PROVIDER` | No | AI backend: `auto` \| `gemini` \| `openai` \| `off` (default: `auto`) | — |
| `GEMINI_API_KEY` | Optional | Google Gemini threat classification and report generation | [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey) |
| `OPENAI_API_KEY` | Optional | OpenAI fallback for classification (GPT-4o-mini) | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) |
| `GEMINI_MODEL` | No | Gemini model to use (default: `gemini-flash-latest`) | — |
| `GEMINI_MAX_RPM` / `GEMINI_MAX_RPD` | No | Local free-tier guard: max Gemini requests per minute / per day (defaults: `5` / `20`) | — |
| `AI_MODEL` | No | OpenAI model to use (default: `gpt-4o-mini`) | — |
| `AI_CLASSIFIER_TIMEOUT_MS` | No | Max ms to wait for AI before fallback (default: `800`) | — |
| `AI_REPORT_TIMEOUT_MS` | No | Max ms to wait for AI report generation; `0` = no timeout | — |
| `CORS_ORIGIN` | No | Comma-separated browser origins allowed to call the API (default: the local Vite dev/preview origins) | — |
| `AI_RATE_LIMIT_PER_MIN` | No | Per-client rate limit for `/api/analyze` and `/api/report` (default: `10`) | — |
| `ABUSE_REFRESH_MS` | No | How often the AbuseIPDB blacklist is refreshed; the default of 6 hours keeps free-plan quota safe | — |
| `SENSOR_LAT` / `SENSOR_LNG` | No | Location of the neutral monitoring node all arcs end at (default: `20` / `0`) | — |

See `server/.env.example` for the full list of advanced AI tuning parameters.

---

##  Features

- **Multi-source threat fusion** —> Aggregates events from AbuseIPDB, OTX, Shodan, and IPInfo in a single pipeline with deduplication
- **AI-powered classification** —> Gemini and/or OpenAI classify ambiguous threat signals into DDoS, Malware, or Scan categories; falls back to rule-based scoring when AI is unavailable
- **3D interactive globe** —> Animated attack arcs rendered in real time using Globe.gl and Three.js; click any arc to inspect the full threat record
- **SOC dashboard panels** —> Live threat feed with severity filters, a threat-level summary, top origins, an observation timeline, a severity mix, and data-source health
- **Fallback chain** —> Gracefully degrades: live APIs → cached or partial data → clearly labelled sample IPs when the AbuseIPDB list is unavailable; the UI shows a banner and badges partial data
- **Simulation mode** —> Replays historical incidents (WannaCry, Mirai) phase by phase with playback controls; runs entirely in the browser and is clearly labelled as illustrative
- **AI report generator** —> One-click incident report for any live threat (Gemini or OpenAI) with a MITRE ATT&CK mapping

---

## 🏗 Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                     External APIs                            │
│  AbuseIPDB │ AlienVault OTX │ Shodan │ IPInfo               │
└──────────────────────┬───────────────────────────────────────┘
                       │ HTTP
                       ▼
┌──────────────────────────────────────────────────────────────┐
│              Express Backend  (server/index.js)              │
│  • Aggregates & deduplicates events                          │
│  • Rule-based scoring engine                                 │
│  • AI classification layer (Gemini / OpenAI / off)           │
│  • REST: /api/threats /api/analyze /api/report /api/health   │
│  • CORS allowlist, rate limiting, input validation           │
└──────────────────────┬───────────────────────────────────────┘
                       │ JSON over HTTP
                       ▼
┌──────────────────────────────────────────────────────────────┐
│             React Frontend  (src/)                           │
│  • Globe.gl 3D arc visualization                             │
│  • Dashboard panels and charts (Recharts)                    │
│  • Threat report dialog & manual AI analysis                 │
└──────────────────────────────────────────────────────────────┘
```

---

##  Known Limitations

- **API rate limits** —> Free-tier keys (especially AbuseIPDB and Shodan) impose strict rate limits. The AbuseIPDB list is cached for hours and per-IP enrichment for 30 minutes; when a source is unavailable its data is skipped and threats are badged as partial.
- **AI classification requires a valid key** —> With `AI_PROVIDER=auto` and no valid Gemini or OpenAI key configured, the system falls back to rule-based scoring automatically. No error is thrown, but classification depth is reduced.
- **Attack destinations are not observable** —> Threat feeds report sources, not victims, so every live arc ends at one neutral monitoring node instead of a made-up target country.
- **Simulation mode is illustrative** —> Scenario routes are hand-authored historical summaries, not telemetry, and are labelled as simulated.
- **No authentication** —> The API restricts browser origins (CORS), caps request bodies, and rate-limits the paid AI endpoints, but has no user authentication. Do not expose it directly to the public internet; run it locally or behind a reverse proxy with auth.
- **Single-server architecture** —> The backend is a single Node.js process with no clustering or persistent storage. It is not production-hardened.

---

##  Testing & Quality

```bash
npm test        # unit and component tests (Vitest); no network or API keys needed
npm run lint    # ESLint
npm run build   # production build
```

The server tests blank every provider key before loading the app, so they never call real APIs even if `server/.env` exists. The test tooling needs Node.js 20 or newer; the app itself runs on Node.js 18+.

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
