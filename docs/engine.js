/* ScamShield engine — client-side port of app/engine.py.
   Keep rule tables in sync with the Python version; the same test cases
   run against both (tests/test_web_engine.mjs). Running fully in the
   browser means a checked message never leaves the user's device. */
"use strict";

const URGENCY = ["urgent","immediately","act now","right away","within 24 hours","within 12 hours","expires today","final warning","last chance","account will be closed","account will be suspended","will be locked","will be terminated","respond now","do not delay","time sensitive","action required"];
const AUTHORITY_BRANDS = ["irs","social security","ssa","fbi","police","sheriff","court","amazon","paypal","apple","microsoft","google","netflix","bank","chase","wells fargo","bank of america","capital one","venmo","cash app","zelle","fedex","ups","usps","dhl","at&t","verizon","coinbase","irs.gov","medicare","customs"];
const PAYMENT_RAILS = ["gift card","gift cards","bitcoin","crypto","cryptocurrency","wire transfer","wire the money","send money","cash app","western union","moneygram","prepaid card","steam card","google play card","apple gift","itunes card","buy cards"];
const CREDENTIAL_ASKS = ["password","pin code","your pin","social security number","ssn","one-time code","verification code","otp","confirm your identity","verify your account","update your payment","confirm your account","log in to verify","sign in to verify","bank account number","routing number","card number","cvv","date of birth"];
const THREATS = ["arrest","warrant","legal action","lawsuit","prosecution","jail","criminal","penalty","fine will","deport"];
const PRIZE_LURES = ["you have won","you've won","you won","congratulations","lottery","prize","claim your reward","free iphone","free gift","you have been selected","you've been selected","winner","gift waiting","reward points expire"];
const SECRECY = ["don't tell anyone","do not tell anyone","keep this secret","don't tell your family","stay on the phone","do not hang up","don't call the bank","do not contact"];
const JOB_MULE = ["deposit the check","deposit this check","process payments","easy money","work from home and earn","no experience needed","send the rest back","keep a commission","mystery shopper","reshipping","payment processor"];
const ROMANCE_INVEST = ["guaranteed profit","double your money","investment opportunity","i love you","my darling","send money for my flight","military deployment","stuck overseas","customs fee"];
const SHORTENERS = new Set(["bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly","rb.gy","shorturl.at","tiny.cc"]);
const SUSPICIOUS_TLDS = new Set([".xyz",".top",".click",".buzz",".work",".live",".online",".site",".fun",".icu",".rest",".monster",".best",".today"]);
const LINK_PRESSURE_WORDS = ["verify","login","signin","secure","update","confirm","unlock","restore","claim","suspended"];
const URL_RE = /https?:\/\/[^\s<>"')\]]+|www\.[^\s<>"')\]]+/gi;
const GENERIC_GREETING_RE = /\b(dear (customer|user|client|member|account holder|friend))\b/i;

const hits = (low, phrases) => phrases.filter(p => low.includes(p));
const uniq = arr => [...new Set(arr)];

function checkLinks(urls) {
  const flags = [];
  for (const raw of urls) {
    const url = raw.startsWith("http") ? raw : "http://" + raw;
    let host = "";
    try { host = new URL(url).hostname.toLowerCase(); } catch { host = ""; }
    if (!host) continue;
    if (SHORTENERS.has(host)) flags.push({category:"link",label:"Shortened link hides the real destination",detail:`'${host}' links are a favourite scammer tool because you cannot see where they really go until you click.`,points:14});
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) flags.push({category:"link",label:"Link goes to a raw IP address, not a company website",detail:"Real banks and companies never send links like http://203.0.113.5/... — IP-address links are a classic phishing sign.",points:18});
    if (host.includes("xn--")) flags.push({category:"link",label:"Look-alike (punycode) domain",detail:"The domain uses encoded characters that can make a fake site look like a real brand (e.g. 'arnazon' posing as 'amazon').",points:18});
    const tld = host.includes(".") ? "." + host.split(".").pop() : "";
    if (SUSPICIOUS_TLDS.has(tld)) flags.push({category:"link",label:`Unusual domain ending (${tld})`,detail:"Cheap, throwaway domain endings are used heavily in scam campaigns. A real company uses its normal .com site.",points:8});
    const afterScheme = url.split("://",2)[1] || "";
    if ((afterScheme.split("/",1)[0] || "").includes("@")) flags.push({category:"link",label:"'@' trick in the link",detail:"An '@' in a link makes your browser ignore everything before it — the address you see is not the site you visit.",points:16});
    const pressure = LINK_PRESSURE_WORDS.filter(w => url.toLowerCase().includes(w));
    if (pressure.length) flags.push({category:"link",label:"Link itself pushes you to log in / verify",detail:"The link contains pressure words (" + uniq(pressure).sort().join(", ") + "). Genuine services ask you to open their app or type their address yourself.",points:8});
    if (url.toLowerCase().startsWith("http://") && !SHORTENERS.has(host)) flags.push({category:"link",label:"Link is not encrypted (http, not https)",detail:"An unencrypted page asking for logins or payment details should never be trusted.",points:6});
  }
  return flags;
}

function adviceFor(flags, level) {
  const cats = new Set(flags.map(f => f.category));
  const advice = [];
  if (level === "likely_scam" || level === "high_risk") advice.push("Do NOT click the link, call the number in the message, or reply to it.");
  if (cats.has("payment")) advice.push("Never pay with gift cards, crypto, wire transfer or a payment app for an unexpected demand — legitimate organisations never ask for these. Money sent this way is almost impossible to get back.");
  if (cats.has("credential")) advice.push("Never share a password, PIN or one-time code. Your bank will never ask for the code it just sent you.");
  if (cats.has("impersonation") || cats.has("link")) advice.push("If you're worried it might be real, contact the company yourself using the number on its official website, your card, or its app — never the contact details in the message.");
  if (cats.has("threat")) advice.push("Real police, courts and tax agencies do not threaten arrest by text/email or demand instant payment. Hang up / delete, then check through official channels.");
  if (cats.has("secrecy")) advice.push("Being told to keep it secret or stay on the phone is itself a giant red flag — tell a family member or friend before doing anything.");
  advice.push("In the US you can report it at ReportFraud.ftc.gov and forward scam texts to 7726 (SPAM).");
  if (level === "safe") return ["No strong scam signals found. Still: don't share codes or passwords with anyone who contacted you unexpectedly, and open banking/shopping apps directly instead of tapping links."];
  return advice;
}

function analyze(text) {
  text = (text || "").trim();
  const low = " " + text.toLowerCase().replace(/\s+/g, " ") + " ";
  const flags = [];
  const urls = text.match(URL_RE) || [];
  if (urls.length) {
    flags.push({category:"link",label:"Contains a clickable link",detail:"A link isn't proof of a scam, but most phishing starts with one. The checks below look at where it points.",points:4});
    flags.push(...checkLinks(urls));
  }
  const urg = hits(low, URGENCY);
  if (urg.length) flags.push({category:"urgency",label:"Pressure / urgency language",detail:"Scammers rush you so you don't stop to think. Found: " + urg.slice(0,4).map(u=>`'${u}'`).join(", ") + ".",points:Math.min(10 + 3*urg.length, 20)});
  const brands = hits(low, AUTHORITY_BRANDS);
  const problemContext = ["suspended","unusual","unauthorised","unauthorized","problem","verify","locked","blocked","payment failed","declined","delivery","package","refund","charge","owe","tax"].some(w => low.includes(w));
  if (brands.length && problemContext) flags.push({category:"impersonation",label:"Claims to be a trusted organisation with a problem",detail:"The message invokes " + uniq(brands).slice(0,3).join(", ") + " together with a problem/urgent action. Impersonation is the #1 scam pattern worldwide.",points:18});
  else if (brands.length) flags.push({category:"impersonation",label:"Mentions a trusted organisation",detail:"Naming " + uniq(brands).slice(0,3).join(", ") + " is common in impersonation scams — check the sender, not the logo.",points:6});
  const pay = hits(low, PAYMENT_RAILS);
  if (pay.length) flags.push({category:"payment",label:"Asks for payment via a hard-to-reverse method",detail:"Requested via: " + uniq(pay).sort().slice(0,4).join(", ") + ". These rails are chosen precisely because refunds are near-impossible.",points:22});
  const cred = hits(low, CREDENTIAL_ASKS);
  if (cred.length) flags.push({category:"credential",label:"Asks for sensitive credentials / codes",detail:"Asks for: " + uniq(cred).sort().slice(0,4).join(", ") + ". No legitimate company asks for these by text or email.",points:20});
  const thr = hits(low, THREATS);
  if (thr.length) flags.push({category:"threat",label:"Threats of arrest / legal action",detail:"Threat language found: " + uniq(thr).sort().slice(0,3).join(", ") + ". Fear is the scammer's main tool.",points:16});
  const prize = hits(low, PRIZE_LURES);
  if (prize.length) flags.push({category:"lure",label:"Prize / lottery / you-have-won lure",detail:"You cannot win a contest you never entered. 'Prizes' that ask for a fee, a click or your details are bait.",points:16});
  const sec = hits(low, SECRECY);
  if (sec.length) flags.push({category:"secrecy",label:"Tells you to keep it secret / stay on the line",detail:"Isolating you from people who would warn you is a deliberate control tactic in phone and text scams.",points:18});
  const job = hits(low, JOB_MULE);
  if (job.length) flags.push({category:"job",label:"Money-mule / fake-job pattern",detail:"Depositing a cheque and forwarding money makes YOU liable when the cheque bounces — a well-documented recruitment scam.",points:18});
  const rom = hits(low, ROMANCE_INVEST);
  if (rom.length) flags.push({category:"lure",label:"Romance / guaranteed-investment pattern",detail:"Guaranteed returns and online-relationship money requests are the core of 'pig-butchering' scams.",points:16});
  if (GENERIC_GREETING_RE.test(text) && urls.length) flags.push({category:"impersonation",label:"Generic greeting ('Dear customer') with a link",detail:"Your real bank knows your name. Mass phishing uses generic greetings because it is sent to thousands at once.",points:8});
  const letters = [...text].filter(c => /[a-zA-Z]/.test(c));
  if (letters.length > 40 && letters.filter(c => c >= "A" && c <= "Z").length / letters.length > 0.55) flags.push({category:"urgency",label:"Message is mostly SHOUTING in capitals",detail:"Excessive capitals are used to create panic and stop careful reading.",points:5});
  const score = Math.max(0, Math.min(100, flags.reduce((s,f)=>s+f.points,0)));
  let level, headline;
  if (score >= 65) { level="high_risk"; headline="High risk — this looks like a scam"; }
  else if (score >= 40) { level="likely_scam"; headline="Likely a scam — treat with real caution"; }
  else if (score >= 15) { level="caution"; headline="Some warning signs — slow down and verify"; }
  else { level="safe"; headline="No strong scam signals found"; }
  return {score, level, headline, flags, urls, advice: adviceFor(flags, level)};
}

if (typeof module !== "undefined" && module.exports) module.exports = { analyze };
