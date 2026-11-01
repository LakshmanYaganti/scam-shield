# 🛡️ ScamShield

**🔴 Live demo: https://lakshmanyaganti.github.io/scam-shield/** — runs 100% in your browser (`docs/` build); the same engine also ships as a FastAPI app (`app/`).

**Paste a suspicious text, email or link → get a plain-English verdict in seconds.**

Americans lost **$12.5B to fraud** in a year (FTC), 57% of adults were targeted in the
past year, and AI voice-clone phishing surged 442%. ScamShield is the simplest possible
defence: one box, one button, one clear answer — built for everyone, especially the
parents and grandparents scammers target most.

![status](https://img.shields.io/badge/version-1.0.0-brightgreen) ![tests](https://img.shields.io/badge/tests-17%20passing-brightgreen) ![privacy](https://img.shields.io/badge/privacy-nothing%20stored-blue)

## What it does

- **Risk score 0–100** with a verdict: Safe / Caution / Likely scam / High risk
- **Every red flag named and explained** — urgency pressure, brand impersonation,
  gift-card/crypto/wire payment demands, credential & one-time-code asks, threats,
  secrecy tactics, prize lures, money-mule job patterns, and link forensics
  (URL shorteners, look-alike punycode domains, raw-IP links, `@` tricks,
  throwaway TLDs, http logins)
- **Tailored next steps** for the exact pattern found + how to report it (FTC / 7726)
- **Family safety plan** built in — including the family code-word defence against
  AI voice-clone "grandparent scams"
- **Shareable report** — copy a plain-English report to send to a family member

## Privacy by design

Analysis is **rule-based and stateless**: the message is scored in memory and is
never stored, logged, or sent to any third party or LLM. That's the whole point —
a scam checker shouldn't be another thing you have to trust with your data.

## Run it

```bash
# local
pip install -r requirements.txt        # plus: pip install pytest httpx (dev/tests)
uvicorn app.main:app --port 8000       # → http://localhost:8000

# docker
docker build -t scam-shield . && docker run -p 8000:8000 scam-shield
```

## API

| Endpoint | What |
|---|---|
| `GET /health` | Liveness + version |
| `GET /api/examples` | Demo messages (scam classics + one normal) |
| `POST /api/check` | Body `{"text": "..."}` → score, level, flags[], urls[], advice[] |

Input is capped at 10,000 chars. Interactive docs at `/docs` (FastAPI).

## Tests

```bash
python -m pytest tests/ -q     # 17 tests: engine classics, safe messages, API
```

## Why rules, not an LLM?

Deterministic = explainable, free to run, offline-capable, and testable. Every point
in the score traces to a flag a user can read and learn from — the goal is not just a
verdict, it's teaching the pattern so the *next* scam gets spotted without us.

## Roadmap (v1.1+)

- Screenshot upload (OCR a screenshot of a text message)
- Browser extension + share-sheet target ("Share → ScamShield")
- Sender/domain reputation check (SPF-style header paste)
- Multilingual rule packs (Spanish first)
- Optional family mode: check result auto-shared with a trusted contact

## Idea research

See `IDEA-RESEARCH.md` — the global-news scan and the 5-idea scorecard this app won.
