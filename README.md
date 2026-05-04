# Log Threat Analyzer

A defensive log-analysis CLI that ingests authentication logs and flags suspicious patterns: brute-force attempts, password spraying, distributed credential stuffing, and successful logins that follow a burst of failures.

Zero runtime dependencies, Node 20+.

## Supported Log Formats

The analyzer auto-detects the format on a per-line basis.

### Simple

```
<timestamp> <ip> <user> SUCCESS|FAIL <message>
```

### sshd / auth.log

Standard `/var/log/auth.log` lines:

```
Apr 30 09:01:02 host sshd[1234]: Failed password for invalid user admin from 203.0.113.12 port 51234 ssh2
Apr 30 09:02:00 host sshd[1029]: Accepted password for rene from 10.0.0.5 port 22 ssh2
Apr 30 09:01:35 host sshd[1028]: Invalid user ubuntu from 203.0.113.12
```

### JSON line

```json
{"timestamp":"2026-04-30T09:00:00Z","ip":"10.0.0.5","user":"rene","outcome":"FAIL","message":"bad password"}
```

## Detections

| Pattern | Severity | When |
| --- | --- | --- |
| `BRUTE_FORCE_PATTERN` | high | N+ failures from one IP within a sliding time window |
| `SUCCESS_AFTER_FAILURES` | high | An IP that produced N+ failures eventually succeeded — possible compromise |
| `PASSWORD_SPRAY_PATTERN` | medium | One IP attempting many distinct usernames |
| `DISTRIBUTED_TARGETING` | medium | One user being targeted from multiple IPs (credential stuffing) |
| `MULTIPLE_SUCCESS_LOCATIONS` | low | One user successfully logged in from many IPs |

Findings are sorted by severity in the output.

## Install

```bash
git clone https://github.com/rmayen/log-threat-analyzer.git
cd log-threat-analyzer
npm test
```

No `npm install` required — the tool only uses Node's standard library.

## Usage

```bash
node src/cli.js sample/auth.log
node src/cli.js --format text sample/auth.log
node src/cli.js --threshold 3 --window 300 sample/auth.log
node src/cli.js --output report.json sample/auth.log sample/sshd.log
```

### Options

| Flag | Description |
| --- | --- |
| `--format, -f <fmt>` | `json` (default) or `text` |
| `--output, -o <path>` | Write report to file instead of stdout |
| `--threshold <n>` | Failed-login count to flag brute force (default 5) |
| `--spray-threshold <n>` | Distinct usernames per IP to flag spray (default 3) |
| `--window <seconds>` | Sliding-window length for brute-force detection (default 600) |
| `--help, -h` | Show usage |

Exit code is `2` if any high-severity finding was raised, `0` otherwise.

## Example Output (text)

```
events analyzed: 15
time range: 2026-04-30T08:55:00Z → 2026-04-30T17:15:42Z
unique ips: 7  unique users: 9
successes: 4  failures: 11

findings (4):
  [HIGH]    BRUTE_FORCE_PATTERN
           7 failed logins from 203.0.113.12 within window
  [HIGH]    SUCCESS_AFTER_FAILURES
           203.0.113.12 had 7 failures then succeeded as rene — possible credential compromise
  [MEDIUM]  PASSWORD_SPRAY_PATTERN
           203.0.113.12 attempted logins against 7 users: admin, root, rene, deploy, test
  [MEDIUM]  DISTRIBUTED_TARGETING
           alice was targeted from 4 different IPs — possible credential stuffing target
```

## Tests

```bash
npm test
```

Twelve unit tests cover the parsers, the windowed detection, severity ordering, and edge cases (empty input, malformed lines, clean activity).

## Security Note

This project is defensive. It only reads existing logs and produces a report; it does not scan, fuzz, or send any traffic.

## My Role

Solo developer. Designed the detection model, implemented the multi-format log parser (simple, sshd `auth.log`, JSON line), built the sliding-window brute-force and password-spray detectors, and wrote the test suite covering parsers, severity ordering, and malformed-input handling. The project uses only Node's standard library to keep the tool dependency-free for incident-response use.

## What I Learned

Tuning detections is harder than writing them. A threshold of 5 failures in 10 minutes catches obvious brute-force but misses slow attackers; lowering it produces false positives on a normal user mistyping a password. I ended up exposing the threshold and window as CLI flags so the user can tune for their environment, and added `SUCCESS_AFTER_FAILURES` so the report still surfaces the most important case — a likely compromise — even when the brute-force threshold isn't tripped. I also learned how much format-handling code a "simple" log tool actually needs: the parser layer is roughly half the project.
