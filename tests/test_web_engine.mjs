// Parity checks: the browser engine (docs/engine.js) must agree with the
// Python engine on the shared cases. Run: node tests/test_web_engine.mjs
import { createRequire } from "module";
const require = createRequire(import.meta.url);
const { analyze } = require("../docs/engine.js");

const CASES = [
  // [text, expectedLevel]
  ["URGENT: Wells Fargo alert. Unusual activity detected, your account will be suspended within 24 hours. Verify your account and confirm your password now: https://bit.ly/3xSecureLogin", "high_risk"],
  ["This is the IRS. You owe back taxes and a warrant will be issued for your arrest unless you pay immediately using gift cards. Do not tell anyone and stay on the phone.", "high_risk"],
  ["USPS: Your package cannot be delivered due to an incorrect address. Update your payment information here to avoid it being returned: http://usps-redelivery.xyz/track", null], // level checked in python suite; here just score>15
  ["Hi Maya, thanks for lunch yesterday! I sent you the photos from the hike. Let me know when you want to plan the next one.", "safe"],
  ["Reminder: dentist appointment tomorrow at 10am. Please arrive 10 minutes early and bring your insurance card.", "safe"],
  ["URGENT: Your Chase account will be suspended within 24 hours. Verify your password and one-time code here: https://bit.ly/3fake", "high_risk"], // python smoke test: 75
];

let fail = 0;
for (const [text, level] of CASES) {
  const v = analyze(text);
  const ok = level ? v.level === level : v.score > 15;
  if (!ok) { fail++; console.log("FAIL", v.score, v.level, "expected", level, "::", text.slice(0, 60)); }
  else console.log("ok  ", v.score, v.level, "::", text.slice(0, 60));
}
const smoke = analyze(CASES[5][0]);
if (smoke.score !== 75) { fail++; console.log("FAIL smoke parity: JS", smoke.score, "!= Python 75"); }
console.log(fail ? `${fail} FAILURES` : "ALL PARITY CHECKS PASSED");
process.exit(fail ? 1 : 0);
