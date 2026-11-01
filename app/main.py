"""ScamShield — paste a suspicious message, get a plain-English verdict.

Production notes:
- Stateless by design: the submitted text is analysed in memory and never
  stored, logged, or sent to any third party.
- Input is size-capped; the API returns structured flags so any client
  (this web page, a future mobile app, a family WhatsApp bot) can render them.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from app.engine import analyze

STATIC = Path(__file__).parent / "static"
MAX_CHARS = 10_000

app = FastAPI(
    title="ScamShield",
    description="Plain-English scam checker for texts, emails and links.",
    version="1.0.0",
)


class CheckRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_CHARS,
                      description="The suspicious message, email or link text")


class FlagOut(BaseModel):
    category: str
    label: str
    detail: str
    points: int


class CheckResponse(BaseModel):
    score: int
    level: str
    headline: str
    flags: list[FlagOut]
    urls: list[str]
    advice: list[str]


EXAMPLES = [
    {
        "name": "Fake bank alert",
        "text": "URGENT: Wells Fargo alert. Unusual activity detected, your "
                "account will be suspended within 24 hours. Verify your "
                "account and confirm your password now: "
                "https://bit.ly/3xSecureLogin",
    },
    {
        "name": "Package delivery scam",
        "text": "USPS: Your package cannot be delivered due to an incorrect "
                "address. Update your payment information here to avoid it "
                "being returned: http://usps-redelivery.xyz/track",
    },
    {
        "name": "Gift-card tax scam",
        "text": "This is the IRS. You owe back taxes and a warrant will be "
                "issued for your arrest unless you pay immediately using "
                "gift cards. Do not tell anyone and stay on the phone.",
    },
    {
        "name": "A normal message",
        "text": "Hi Maya, thanks for lunch yesterday! I sent you the photos "
                "from the hike. Let me know when you want to plan the next one.",
    },
]


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "scam-shield", "version": "1.0.0"}


@app.get("/api/examples")
def examples() -> dict:
    return {"examples": EXAMPLES}


@app.post("/api/check", response_model=CheckResponse)
def check(payload: CheckRequest) -> CheckResponse:
    v = analyze(payload.text)
    return CheckResponse(
        score=v.score, level=v.level, headline=v.headline,
        flags=[FlagOut(category=f.category, label=f.label,
                       detail=f.detail, points=f.points) for f in v.flags],
        urls=v.urls, advice=v.advice,
    )


@app.get("/")
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")
