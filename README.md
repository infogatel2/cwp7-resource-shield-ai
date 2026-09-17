# CWP7 Resource Shield AI — Hackathon Edition

AI-assisted server-defense analyst for CWP7, built for the **Nebius x NVIDIA Global AI Hackathon 2026**.

> This repository is a deliberately separated open-source hackathon edition. It does **not** contain the proprietary commercial CWP7 Resource Shield detection/licensing engine.

## What it does

Resource Shield AI turns structured server-security telemetry into an operator-ready incident explanation. The hackathon flow is:

`Resource Shield telemetry → Nebius Token Factory → NVIDIA Nemotron → defensive incident analysis`

It produces:

- severity and confidence
- attack-pattern explanation
- evidence summary
- affected assets
- indicators
- safe defensive recommendations
- customer-safe incident report

## Significant hackathon update

The commercial CWP7 Resource Shield project existed before the hackathon submission period. During the hackathon, this project adds a **new AI Security Analyst architecture**, a **Nebius Token Factory runtime integration**, **NVIDIA Nemotron reasoning**, a standalone demonstration UI/API, and an open-source telemetry adapter designed to consume sanitized Resource Shield incident data.

## Required hackathon technology

The runtime LLM call uses the **OpenAI-compatible Nebius Token Factory API** and is configured for an NVIDIA Nemotron model.

The model can be set explicitly with `NEBIUS_MODEL`. If left blank, the demo queries the Token Factory model list at runtime and selects an available NVIDIA Nemotron model automatically.

Official Nebius endpoint:

```text
https://api.tokenfactory.nebius.com/v1/
```

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env` and add your Nebius Token Factory API key:

```text
NEBIUS_API_KEY=your_key_here
```

Run:

```bash
uvicorn app:app --host 0.0.0.0 --port 8080
```

Open:

```text
http://localhost:8080
```

## Provider preflight

Before starting the dashboard, verify that the same `.env` key can perform both model discovery and inference:

```bash
python verify_nebius.py
```

A healthy setup prints both `Model-list authentication: OK` and `Chat-completion authentication: OK`. The script never prints the API key.

### If `/models` works but chat returns 401

This means the key can reach Token Factory but inference authentication is being rejected. Create a fresh Token Factory API key in the same project, replace `NEBIUS_API_KEY` in `.env`, and rerun `python verify_nebius.py`. Also confirm that billing/credits are active for that Token Factory project.

The app deliberately loads `.env` with override enabled so a stale shell-level `NEBIUS_API_KEY` cannot silently replace the project key.

## Demo without a key

For development, `DEMO_FALLBACK=1` returns a deterministic local defensive analysis. This exists only so the UI can be developed without spending inference credits.

**The final Devpost demonstration must use a real Nebius Token Factory runtime call.** When `NEBIUS_API_KEY` is configured, the UI badge changes to `LIVE NEMOTRON` and `/api/analyze` calls Nebius.

## Optional live Resource Shield telemetry

On an authorized CWP7 server, point the demo to a Resource Shield `status.json`:

```text
RESOURCE_SHIELD_STATUS_PATH=/var/lib/freespirits-resource-shield/status.json
```

Only the newest structured detection is adapted for AI analysis. The hackathon app does not need access to raw customer website content or credentials.

## API

Health check:

```bash
curl http://localhost:8080/api/health
```

Current demo incident:

```bash
curl http://localhost:8080/api/demo-incident
```

Analyze an incident:

```bash
curl -X POST http://localhost:8080/api/analyze \
  -H 'Content-Type: application/json' \
  --data @sample_data/coordinated_wordpress_attack.json
```

## Security design

The AI component is **advisory and defensive**. It does not autonomously execute arbitrary shell commands, exploit systems, scan third parties, or retaliate. The system prompt requires evidence-aware analysis and reversible defensive recommendations.

The demo intentionally avoids sending passwords, API keys, request bodies, WordPress content, customer data, or raw authentication logs to the model.

## Commercial vs hackathon edition

The production commercial product contains additional proprietary components, including detection heuristics, CWP integration, licensing, Cloudflare automation, HA synchronization, and operational safeguards. Those components are not licensed under this repository's MIT license.

This repository demonstrates the new hackathon AI layer and a reproducible incident-analysis pipeline.

## Contest track

Target track: **Best Apps and Agents**.

## License

MIT — applies only to the files in this repository.

## Nemotron three-tier analysis strategy

The hackathon account exposes three especially useful NVIDIA Nemotron variants, so the project uses them intentionally rather than treating every incident the same:

- **Fast Triage** → `nvidia/NVIDIA-Nemotron-3-Nano-30B-A3B`
- **Standard Analyst** → `nvidia/nemotron-3-super-120b-a12b`
- **Deep Investigation** → `nvidia/Nemotron-3-Ultra-550b-a55b`

This lets an operator use a smaller model for fast everyday incident triage, Super for the default interactive analyst, and Ultra only when a more careful investigation is justified. The UI exposes all three modes and the API accepts `?mode=triage|standard|deep`.
