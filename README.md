<h1 align="center">🌐 Cyberthreat Visualizer</h1>

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

## 📖 Description

Cyberthreat Visualizer is a full-stack SOC (Security Operations Center) dashboard that aggregates live threat intelligence from multiple OSINT sources, AbuseIPDB, AlienVault OTX, Shodan, and IPInfo and renders the data on an interactive 3D globe. Incoming threat events are automatically classified into attack categories (DDoS, Malware, Port Scan) using a rule-based scoring engine augmented by a Gemini AI or OpenAI layer. The dashboard surface includes real-time arc animations on the globe, a threat feed panel, analyst-grade detail cards, and an AI-powered threat report generator.
<img width="1868" height="1051" alt="Screenshot 2026-07-30 020228" src="https://github.com/user-attachments/assets/36fa7727-97f2-447c-aec6-1c73d7166389" />


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

## ✅ Prerequisites

- **Node.js** `>= 18.x` ([download](https://nodejs.org/))
- **npm** `>= 9.x` (bundled with Node.js)
- API keys for at least one threat intelligence provider (see [Environment Variables](#-environment-variables) below)

---

## 🚀 Installation

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

## ▶️ Running Locally

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

> **Note:** The backend must be running before the frontend will display live data. Without a running backend the app falls back to simulation mode automatically.

---

## 🔑 Environment Variables

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
| `GEMINI_MODEL` | No | Gemini model to use (default: `gemini-2.5-flash`) | — |
| `AI_MODEL` | No | OpenAI model to use (default: `gpt-4o-mini`) | — |
| `AI_CLASSIFIER_TIMEOUT_MS` | No | Max ms to wait for AI before fallback (default: `800`) | — |
| `AI_REPORT_TIMEOUT_MS` | No | Max ms to wait for AI report generation; `0` = no timeout | — |

See `server/.env.example` for the full list of advanced AI tuning parameters.

---

## ✨ Features

- **Multi-source threat fusion** —> Aggregates events from AbuseIPDB, OTX, Shodan, and IPInfo in a single pipeline with deduplication
- **AI-powered classification** —> Gemini and/or OpenAI classify ambiguous threat signals into DDoS, Malware, or Scan categories; falls back to rule-based scoring when AI is unavailable
- **3D interactive globe** —> Animated attack arcs rendered in real time using Globe.gl and Three.js; click any arc to inspect the full threat record
- **SOC dashboard panels** —> Live threat feed, severity heatmap, category distribution charts, top attacker table, and country breakdown
- **Fallback chain** —> Gracefully degrades: live APIs → partial data → simulation mode; degraded data is clearly badged in the UI
- **Simulation mode** —> Works entirely offline with realistic synthetic data; no API keys required to explore the UI
- **AI report generator** —> One-click analyst report summarising active threats using Gemini

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
│  • REST endpoints: /api/threats  /api/report                 │
└──────────────────────┬───────────────────────────────────────┘
                       │ JSON over HTTP
                       ▼
┌──────────────────────────────────────────────────────────────┐
│             React Frontend  (src/)                           │
│  • Globe.gl 3D arc visualization                             │
│  • SOC dashboard panels (Recharts)                           │
│  • Threat detail drawer & AI report panel                    │
└──────────────────────────────────────────────────────────────┘
```

---

## ⚠️ Known Limitations

- **API rate limits** —> Free-tier keys (especially AbuseIPDB and Shodan) impose strict rate limits. When limits are hit, affected sources are skipped and events are badged as `DEGRADED` in the UI.
- **AI classification requires a valid key** —> With `AI_PROVIDER=auto` and no valid Gemini or OpenAI key configured, the system falls back to rule-based scoring automatically. No error is thrown, but classification depth is reduced.
- **Simulation mode uses static data** —> When all live sources are unavailable, the app generates synthetic threat events locally. These are clearly marked as simulated and do not represent real-world attacks.
- **No authentication** —> The Express backend has no API key or auth layer protecting its endpoints. Do not expose it directly to the public internet; run it locally or behind a reverse proxy.
- **Single-server architecture** —> The backend is a single Node.js process with no clustering or persistent storage. It is not production-hardened.

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
