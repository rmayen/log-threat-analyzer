const assert = require("node:assert/strict");
const test = require("node:test");
const { analyze, parseLogLine } = require("../src/analyzer");

test("parses simple authentication log format", () => {
  const event = parseLogLine("2026-04-30T09:00:01Z 10.0.0.5 rene SUCCESS login accepted");

  assert.equal(event.ip, "10.0.0.5");
  assert.equal(event.user, "rene");
  assert.equal(event.outcome, "SUCCESS");
  assert.equal(event.source, "simple");
  assert.ok(typeof event.timestampMs === "number");
});

test("parses sshd Failed password lines", () => {
  const event = parseLogLine("Apr 30 09:01:02 host sshd[1234]: Failed password for invalid user admin from 203.0.113.12 port 51234 ssh2");

  assert.equal(event.outcome, "FAIL");
  assert.equal(event.user, "admin");
  assert.equal(event.ip, "203.0.113.12");
  assert.equal(event.source, "ssh");
});

test("parses sshd Accepted password lines", () => {
  const event = parseLogLine("Apr 30 09:00:01 host sshd[999]: Accepted password for rene from 10.0.0.5 port 22 ssh2");

  assert.equal(event.outcome, "SUCCESS");
  assert.equal(event.user, "rene");
});

test("parses json log lines", () => {
  const event = parseLogLine('{"timestamp":"2026-04-30T09:00:00Z","ip":"10.0.0.5","user":"rene","outcome":"FAIL","message":"bad password"}');

  assert.equal(event.outcome, "FAIL");
  assert.equal(event.source, "json");
});

test("returns null for unparseable lines", () => {
  assert.equal(parseLogLine(""), null);
  assert.equal(parseLogLine("totally garbage"), null);
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

test("respects time-window so old failures don't trigger brute force", () => {
  const lines = [
    "2026-01-01T00:00:00Z 203.0.113.12 admin FAIL bad",
    "2026-01-01T00:01:00Z 203.0.113.12 root FAIL bad",
    "2026-04-30T09:00:00Z 203.0.113.12 deploy FAIL bad",
    "2026-04-30T09:00:30Z 203.0.113.12 test FAIL bad"
  ];

  const report = analyze(lines, { failedThreshold: 4, windowSeconds: 60 });
  assert.equal(report.findings.some((finding) => finding.type === "BRUTE_FORCE_PATTERN"), false);
});

test("flags successful login from an IP that previously had many failures", () => {
  const lines = [
    "2026-04-30T09:01:02Z 203.0.113.12 admin FAIL invalid password",
    "2026-04-30T09:01:09Z 203.0.113.12 root FAIL invalid password",
    "2026-04-30T09:01:14Z 203.0.113.12 rene FAIL invalid password",
    "2026-04-30T09:01:20Z 203.0.113.12 deploy FAIL invalid password",
    "2026-04-30T09:01:27Z 203.0.113.12 test FAIL invalid password",
    "2026-04-30T09:02:00Z 203.0.113.12 rene SUCCESS login accepted"
  ];

  const report = analyze(lines);
  assert.equal(report.findings.some((finding) => finding.type === "SUCCESS_AFTER_FAILURES"), true);
});

test("flags distributed targeting of one user from many IPs", () => {
  const lines = [
    "2026-04-30T09:00:00Z 1.1.1.1 alice FAIL bad",
    "2026-04-30T09:00:01Z 2.2.2.2 alice FAIL bad",
    "2026-04-30T09:00:02Z 3.3.3.3 alice FAIL bad"
  ];

  const report = analyze(lines);
  assert.equal(report.findings.some((finding) => finding.type === "DISTRIBUTED_TARGETING"), true);
});

test("returns no findings for clean activity", () => {
  const lines = [
    "2026-04-30T09:00:00Z 10.0.0.5 rene SUCCESS login accepted",
    "2026-04-30T17:00:00Z 10.0.0.5 rene SUCCESS login accepted"
  ];

  const report = analyze(lines);
  assert.equal(report.findings.length, 0);
  assert.equal(report.eventsAnalyzed, 2);
});

test("counts malformed lines without crashing", () => {
  const report = analyze(["totally garbage", "another bad line", "2026-04-30T09:00:00Z 10.0.0.5 rene SUCCESS ok"]);
  assert.equal(report.eventsAnalyzed, 1);
  assert.equal(report.malformedLines, 2);
});

test("orders findings by severity", () => {
  const lines = [
    "2026-04-30T09:00:00Z 1.1.1.1 alice FAIL bad",
    "2026-04-30T09:00:01Z 2.2.2.2 alice FAIL bad",
    "2026-04-30T09:00:02Z 3.3.3.3 alice FAIL bad",
    "2026-04-30T09:01:02Z 203.0.113.12 admin FAIL invalid password",
    "2026-04-30T09:01:09Z 203.0.113.12 root FAIL invalid password",
    "2026-04-30T09:01:14Z 203.0.113.12 rene FAIL invalid password",
    "2026-04-30T09:01:20Z 203.0.113.12 deploy FAIL invalid password",
    "2026-04-30T09:01:27Z 203.0.113.12 test FAIL invalid password"
  ];

  const report = analyze(lines);
  const severities = report.findings.map((finding) => finding.severity);
  const ranks = severities.map((sev) => ({ high: 3, medium: 2, low: 1 }[sev]));
  for (let i = 1; i < ranks.length; i++) {
    assert.ok(ranks[i] <= ranks[i - 1]);
  }
});
