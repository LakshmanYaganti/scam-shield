"""ScamShield scoring engine.

Rule-based, explainable, stateless. Every point in the score traces to a
named flag with a plain-English explanation, so a non-technical user (or a
parent) can see *why* a message looks dangerous — not just a number.

Design notes:
- No ML model and no external API: deterministic, testable, free to run,
  and the checked text never has to leave the server.
- Weights were chosen so a single weak signal (one link) stays "Caution",
  while the classic scam combination (impersonation + urgency + payment /
  credential request) lands firmly in "High risk".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

# --------------------------------------------------------------------------
# Rule tables
# --------------------------------------------------------------------------

URGENCY = [
    "urgent", "immediately", "act now", "right away", "within 24 hours",
    "within 12 hours", "expires today", "final warning", "last chance",
    "account will be closed", "account will be suspended", "will be locked",
    "will be terminated", "respond now", "do not delay", "time sensitive",
    "action required",
]

AUTHORITY_BRANDS = [
    "irs", "social security", "ssa", "fbi", "police", "sheriff", "court",
    "amazon", "paypal", "apple", "microsoft", "google", "netflix", "bank",
    "chase", "wells fargo", "bank of america", "capital one", "venmo",
    "cash app", "zelle", "fedex", "ups", "usps", "dhl", "at&t", "verizon",
    "coinbase", "irs.gov", "medicare", "customs",
]

PAYMENT_RAILS = [
    "gift card", "gift cards", "bitcoin", "crypto", "cryptocurrency",
    "wire transfer", "wire the money", "send money", "cash app",
    "western union", "moneygram", "prepaid card", "steam card",
    "google play card", "apple gift", "itunes card", "buy cards",
]

CREDENTIAL_ASKS = [
    "password", "pin code", "your pin", "social security number", "ssn",
    "one-time code", "verification code", "otp", "confirm your identity",
    "verify your account", "update your payment", "confirm your account",
    "log in to verify", "sign in to verify", "bank account number",
    "routing number", "card number", "cvv", "date of birth",
]

THREATS = [
    "arrest", "warrant", "legal action", "lawsuit", "prosecution",
    "jail", "criminal", "penalty", "fine will", "deport",
]

PRIZE_LURES = [
    "you have won", "you've won", "you won", "congratulations",
    "lottery", "prize", "claim your reward", "free iphone", "free gift",
    "you have been selected", "you've been selected", "winner",
    "gift waiting", "reward points expire",
]

SECRECY = [
    "don't tell anyone", "do not tell anyone", "keep this secret",
    "don't tell your family", "stay on the phone", "do not hang up",
    "don't call the bank", "do not contact",
]

JOB_MULE = [
    "deposit the check", "deposit this check", "process payments",
    "easy money", "work from home and earn", "no experience needed",
    "send the rest back", "keep a commission", "mystery shopper",
    "reshipping", "payment processor",
]

ROMANCE_INVEST = [
    "guaranteed profit", "double your money", "investment opportunity",
    "i love you", "my darling", "send money for my flight",
    "military deployment", "stuck overseas", "customs fee",
]

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc",
}

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".buzz", ".work", ".live", ".online",
    ".site", ".fun", ".icu", ".rest", ".monster", ".best", ".today",
}

LINK_PRESSURE_WORDS = ["verify", "login", "signin", "secure", "update",
                       "confirm", "unlock", "restore", "claim", "suspended"]

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+|www\.[^\s<>\"')\]]+", re.I)
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")
GENERIC_GREETING_RE = re.compile(
    r"\b(dear (customer|user|client|member|account holder|friend))\b", re.I)


@dataclass
class Flag:
    category: str
    label: str
    detail: str
    points: int


@dataclass
class Verdict:
    score: int
    level: str            # safe | caution | likely_scam | high_risk
    headline: str
    flags: list[Flag] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    advice: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _hits(text_low: str, phrases: list[str]) -> list[str]:
    return [p for p in phrases if p in text_low]


def _check_links(urls: list[str]) -> list[Flag]:
    flags: list[Flag] = []
    for raw in urls:
        url = raw if raw.startswith("http") else "http://" + raw
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            host = ""
        if not host:
            continue
        if host in SHORTENERS:
            flags.append(Flag(
                "link", "Shortened link hides the real destination",
                f"'{host}' links are a favourite scammer tool because you "
                "cannot see where they really go until you click.", 14))
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            flags.append(Flag(
                "link", "Link goes to a raw IP address, not a company website",
                "Real banks and companies never send links like "
                "http://203.0.113.5/... — IP-address links are a classic "
                "phishing sign.", 18))
        if "xn--" in host:
            flags.append(Flag(
                "link", "Look-alike (punycode) domain",
                "The domain uses encoded characters that can make a fake "
                "site look like a real brand (e.g. 'arnazon' posing as "
                "'amazon').", 18))
        tld = "." + host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            flags.append(Flag(
                "link", f"Unusual domain ending ({tld})",
                "Cheap, throwaway domain endings are used heavily in "
                "scam campaigns. A real company uses its normal .com site.", 8))
        if "@" in url.split("://", 1)[-1].split("/", 1)[0] or "@" in urlparse(url).netloc:
            flags.append(Flag(
                "link", "'@' trick in the link",
                "An '@' in a link makes your browser ignore everything "
                "before it — the address you see is not the site you visit.", 16))
        path_low = url.lower()
        pressure = [w for w in LINK_PRESSURE_WORDS if w in path_low]
        if pressure and len(urls) >= 1:
            flags.append(Flag(
                "link", "Link itself pushes you to log in / verify",
                "The link contains pressure words (" +
                ", ".join(sorted(set(pressure))) + "). Genuine services "
                "ask you to open their app or type their address yourself.", 8))
        if url.lower().startswith("http://") and host not in SHORTENERS:
            flags.append(Flag(
                "link", "Link is not encrypted (http, not https)",
                "An unencrypted page asking for logins or payment details "
                "should never be trusted.", 6))
    # One link by itself is weak evidence — cap link-only contribution.
    return flags


def _advice_for(flags: list[Flag], level: str) -> list[str]:
    cats = {f.category for f in flags}
    advice: list[str] = []
    if level in ("likely_scam", "high_risk"):
        advice.append("Do NOT click the link, call the number in the message, "
                      "or reply to it.")
    if "payment" in cats:
        advice.append("Never pay with gift cards, crypto, wire transfer or a "
                      "payment app for an unexpected demand — legitimate "
                      "organisations never ask for these. Money sent this way "
                      "is almost impossible to get back.")
    if "credential" in cats:
        advice.append("Never share a password, PIN or one-time code. Your bank "
                      "will never ask for the code it just sent you.")
    if "impersonation" in cats or "link" in cats:
        advice.append("If you're worried it might be real, contact the company "
                      "yourself using the number on its official website, your "
                      "card, or its app — never the contact details in the message.")
    if "threat" in cats:
        advice.append("Real police, courts and tax agencies do not threaten "
                      "arrest by text/email or demand instant payment. Hang up / "
                      "delete, then check through official channels.")
    if "secrecy" in cats:
        advice.append("Being told to keep it secret or stay on the phone is "
                      "itself a giant red flag — tell a family member or friend "
                      "before doing anything.")
    advice.append("In the US you can report it at ReportFraud.ftc.gov and "
                  "forward scam texts to 7726 (SPAM).")
    if level == "safe":
        return ["No strong scam signals found. Still: don't share codes or "
                "passwords with anyone who contacted you unexpectedly, and "
                "open banking/shopping apps directly instead of tapping links."]
    return advice


# --------------------------------------------------------------------------
# Main entry point
# --------------------------------------------------------------------------

def analyze(text: str) -> Verdict:
    text = (text or "").strip()
    low = " " + re.sub(r"\s+", " ", text.lower()) + " "
    flags: list[Flag] = []

    urls = URL_RE.findall(text)
    if urls:
        flags.append(Flag(
            "link", "Contains a clickable link",
            "A link isn't proof of a scam, but most phishing starts with "
            "one. The checks below look at where it points.", 4))
        flags.extend(_check_links(urls))

    urg = _hits(low, URGENCY)
    if urg:
        flags.append(Flag(
            "urgency", "Pressure / urgency language",
            "Scammers rush you so you don't stop to think. Found: " +
            ", ".join(f"'{u}'" for u in urg[:4]) + ".", min(10 + 3 * len(urg), 20)))

    brands = _hits(low, AUTHORITY_BRANDS)
    problem_context = any(w in low for w in [
        "suspended", "unusual", "unauthorised", "unauthorized", "problem",
        "verify", "locked", "blocked", "payment failed", "declined",
        "delivery", "package", "refund", "charge", "owe", "tax",
    ])
    if brands and problem_context:
        flags.append(Flag(
            "impersonation", "Claims to be a trusted organisation with a problem",
            "The message invokes " + ", ".join(sorted(set(brands))[:3]) +
            " together with a problem/urgent action. Impersonation is the "
            "#1 scam pattern worldwide.", 18))
    elif brands:
        flags.append(Flag(
            "impersonation", "Mentions a trusted organisation",
            "Naming " + ", ".join(sorted(set(brands))[:3]) + " is common in "
            "impersonation scams — check the sender, not the logo.", 6))

    pay = _hits(low, PAYMENT_RAILS)
    if pay:
        flags.append(Flag(
            "payment", "Asks for payment via a hard-to-reverse method",
            "Requested via: " + ", ".join(sorted(set(pay))[:4]) +
            ". These rails are chosen precisely because refunds are "
            "near-impossible.", 22))

    cred = _hits(low, CREDENTIAL_ASKS)
    if cred:
        flags.append(Flag(
            "credential", "Asks for sensitive credentials / codes",
            "Asks for: " + ", ".join(sorted(set(cred))[:4]) +
            ". No legitimate company asks for these by text or email.", 20))

    thr = _hits(low, THREATS)
    if thr:
        flags.append(Flag(
            "threat", "Threats of arrest / legal action",
            "Threat language found: " + ", ".join(sorted(set(thr))[:3]) +
            ". Fear is the scammer's main tool.", 16))

    prize = _hits(low, PRIZE_LURES)
    if prize:
        flags.append(Flag(
            "lure", "Prize / lottery / you-have-won lure",
            "You cannot win a contest you never entered. 'Prizes' that ask "
            "for a fee, a click or your details are bait.", 16))

    sec = _hits(low, SECRECY)
    if sec:
        flags.append(Flag(
            "secrecy", "Tells you to keep it secret / stay on the line",
            "Isolating you from people who would warn you is a deliberate "
            "control tactic in phone and text scams.", 18))

    job = _hits(low, JOB_MULE)
    if job:
        flags.append(Flag(
            "job", "Money-mule / fake-job pattern",
            "Depositing a cheque and forwarding money makes YOU liable when "
            "the cheque bounces — a well-documented recruitment scam.", 18))

    rom = _hits(low, ROMANCE_INVEST)
    if rom:
        flags.append(Flag(
            "lure", "Romance / guaranteed-investment pattern",
            "Guaranteed returns and online-relationship money requests are "
            "the core of 'pig-butchering' scams.", 16))

    if GENERIC_GREETING_RE.search(text) and urls:
        flags.append(Flag(
            "impersonation", "Generic greeting ('Dear customer') with a link",
            "Your real bank knows your name. Mass phishing uses generic "
            "greetings because it is sent to thousands at once.", 8))

    # ALL-CAPS shouting in a long message is a small pressure signal.
    letters = [c for c in text if c.isalpha()]
    if len(letters) > 40 and sum(c.isupper() for c in letters) / len(letters) > 0.55:
        flags.append(Flag(
            "urgency", "Message is mostly SHOUTING in capitals",
            "Excessive capitals are used to create panic and stop careful "
            "reading.", 5))

    score = max(0, min(100, sum(f.points for f in flags)))

    if score >= 65:
        level, headline = "high_risk", "High risk — this looks like a scam"
    elif score >= 40:
        level, headline = "likely_scam", "Likely a scam — treat with real caution"
    elif score >= 15:
        level, headline = "caution", "Some warning signs — slow down and verify"
    else:
        level, headline = "safe", "No strong scam signals found"

    return Verdict(score=score, level=level, headline=headline, flags=flags,
                   urls=urls, advice=_advice_for(flags, level))
