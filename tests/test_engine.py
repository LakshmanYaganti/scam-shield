import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from fastapi.testclient import TestClient

from app.engine import analyze
from app.main import app

client = TestClient(app)


# ---------------- engine: high-risk classics ----------------

def test_bank_phishing_with_shortened_link_is_high_risk():
    v = analyze("URGENT: Wells Fargo alert. Unusual activity detected, your "
                "account will be suspended within 24 hours. Verify your "
                "account and confirm your password now: https://bit.ly/3xFake")
    assert v.level == "high_risk"
    assert v.score >= 65
    cats = {f.category for f in v.flags}
    assert {"urgency", "impersonation", "credential", "link"} <= cats


def test_gift_card_tax_scam_is_high_risk():
    v = analyze("This is the IRS. You owe back taxes and a warrant will be "
                "issued for your arrest unless you pay immediately using "
                "gift cards. Do not tell anyone and stay on the phone.")
    assert v.level == "high_risk"
    cats = {f.category for f in v.flags}
    assert {"payment", "threat", "secrecy"} <= cats


def test_package_scam_with_bad_tld_is_flagged():
    v = analyze("USPS: Your package cannot be delivered. Update your payment "
                "information here: http://usps-redelivery.xyz/track")
    assert v.score >= 15
    assert any(".xyz" in f.label for f in v.flags)


def test_prize_lure_flagged():
    v = analyze("Congratulations! You have won a free iPhone in our lottery. "
                "Claim your reward now before it expires today.")
    assert any(f.category == "lure" for f in v.flags)
    assert v.score >= 15


def test_money_mule_job_flagged():
    v = analyze("Easy money, work from home, no experience needed. We send "
                "you a check, deposit the check and send the rest back, "
                "keep a commission.")
    assert any(f.category == "job" for f in v.flags)


def test_ip_address_link_flagged():
    v = analyze("Verify your account here: http://203.0.113.55/login")
    assert any("IP address" in f.label for f in v.flags)


# ---------------- engine: safe / low-signal ----------------

def test_normal_friendly_message_is_safe():
    v = analyze("Hi Maya, thanks for lunch yesterday! I sent you the photos "
                "from the hike. Let me know when you want to plan the next one.")
    assert v.level == "safe"
    assert v.score < 15


def test_plain_reminder_is_safe():
    v = analyze("Reminder: dentist appointment tomorrow at 10am. Please "
                "arrive 10 minutes early and bring your insurance card.")
    assert v.level == "safe"


def test_single_normal_link_alone_is_not_high_risk():
    v = analyze("Here is the article I mentioned: https://example.com/news")
    assert v.level in ("safe", "caution")
    assert v.score < 40


def test_empty_text_scores_zero():
    v = analyze("")
    assert v.score == 0
    assert v.level == "safe"


def test_score_never_exceeds_100():
    v = analyze("URGENT arrest warrant IRS gift card bitcoin password "
                "verification code congratulations you have won lottery "
                "do not tell anyone stay on the phone account will be "
                "suspended immediately https://bit.ly/x http://a.xyz/login")
    assert v.score <= 100


def test_advice_present_for_scam():
    v = analyze("Pay with gift cards now, your account will be suspended.")
    assert any("gift card" in a.lower() for a in v.advice)
    assert any("ReportFraud" in a for a in v.advice)


# ---------------- API ----------------

def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_check_endpoint():
    r = client.post("/api/check", json={"text": "URGENT verify your password "
                                        "now or account will be suspended "
                                        "https://bit.ly/abc"})
    assert r.status_code == 200
    body = r.json()
    assert body["score"] >= 40
    assert body["flags"] and body["advice"]


def test_check_rejects_empty():
    r = client.post("/api/check", json={"text": ""})
    assert r.status_code == 422


def test_examples_endpoint():
    r = client.get("/api/examples")
    assert r.status_code == 200
    assert len(r.json()["examples"]) >= 3


def test_homepage_served():
    r = client.get("/")
    assert r.status_code == 200
    assert "ScamShield" in r.text
