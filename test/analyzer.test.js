const assert = require("node:assert/strict");
const test = require("node:test");
const { analyze, parseLogLine } = require("../src/analyzer");

test("parses supported authentication log format", () => {
  const event = parseLogLine("2026-04-30T09:00:01Z 10.0.0.5 rene SUCCESS login accepted");

  assert.equal(event.ip, "10.0.0.5");
  assert.equal(event.user, "rene");
  assert.equal(event.outcome, "SUCCESS");
});

test("flags brute force and password spray patterns", () => {
  const lines = [
    "2026-04-30T09:01:02Z 203.0.113.12 admin FAIL invalid password",
    "2026-04-30T09:01:09Z 203.0.113.12 root FAIL invalid password",
    "2026-04-30T09:01:14Z 203.0.113.12 rene FAIL invalid password",
    "2026-04-30T09:01:20Z 203.0.113.12 deploy FAIL invalid password",
    "2026-04-30T09:01:27Z 203.0.113.12 test FAIL invalid password"
  ];

  const report = analyze(lines);

  assert.equal(report.findings.some((finding) => finding.type === "BRUTE_FORCE_PATTERN"), true);
  assert.equal(report.findings.some((finding) => finding.type === "PASSWORD_SPRAY_PATTERN"), true);
});
