# Idea research — simple apps that help in real life (scanned 31 Oct 2026)

## What the news says people are actually losing / struggling with

1. **Scams everywhere, getting AI-powered.** Americans lost over **$12.5 billion to fraud**
   (FTC, +25% YoY); 57% of adults across 42 countries were targeted in the past year.
   Deepfake fraud caused **$200M+ in losses in Q1 2025 alone**; voice-phishing surged 442%.
   Subscription traps drain **~$2.8B/year** from US households. The wider "annoyance economy"
   (junk fees, phone scams, robocalls, hard cancellations) costs **~$166B/year**.
2. **Medication non-adherence in older adults: 20–55%** don't take medicines as prescribed —
   a leading cause of preventable hospitalisation, driven by complex regimens and living alone.
3. **Everyday admin overload** — solopreneur/small-business AI tools were the biggest launch
   theme of Oct 2026 (inbox triage, daily briefs, to-do radar), i.e. people pay to not drown in admin.

## Shortlist scored (Problem size / Frequency / Simplicity / Fit for Lakshman / Build-in-a-day)

| # | Idea | Problem | Freq | Simple | Fit | Total /50 | Verdict |
|---|------|---------|------|--------|-----|-----------|---------|
| 1 | **ScamShield — paste a suspicious text/email/link, get a plain-English risk verdict** | 10 | 10 | 9 | 10 | **47** | **BUILD — winner** |
| 2 | Subscription Leak Finder — list every recurring charge, cancel reminders | 8 | 7 | 7 | 8 | 38 | Strong #2; needs manual entry / bank data |
| 3 | Family Med Reminder — dose schedule + "taken" confirm for a parent | 9 | 9 | 7 | 6 | 37 | Helpful; health-liability + notification infra |
| 4 | Fridge Expiry Saver — track expiry dates, use-it-first list | 7 | 8 | 8 | 5 | 34 | Simple, crowded, generic |
| 5 | Receipt & Warranty Vault — photo a receipt, never lose proof again | 6 | 6 | 9 | 6 | 33 | Useful, low urgency |

## Why ScamShield wins

- **Everyone is a user**: you, your parents, your friends — everyone gets scam texts weekly.
- **Perfect author fit**: built by a fraud Data Scientist at Square — credible in a way a
  generic to-do app never is. Extends his fraud-detection-ml flagship into a product people can touch.
- **Truly simple**: one box, one button, one verdict. No account, no bank login, no download.
- **Privacy-first by design**: analysis is rule-based and stateless — the message is never stored.
  That's a feature competitors that send text to an LLM can't honestly claim the same way.
- **Production-ready in one build**: FastAPI + one static page, Docker, tests, no external APIs to pay for.
