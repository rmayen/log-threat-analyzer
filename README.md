# Log Threat Analyzer

A defensive log analysis CLI that reviews authentication logs and flags suspicious patterns such as repeated failed logins, password spraying, and successful logins from multiple locations.

## Supported Log Format

```text
timestamp ip username SUCCESS|FAIL message
```

Example:

```text
2026-04-30T09:01:02Z 203.0.113.12 admin FAIL invalid password
```

## Features

- Parses simple authentication logs
- Detects repeated failed login patterns
- Detects possible password spraying across multiple usernames
- Detects successful logins for a user from multiple IP addresses
- Outputs structured JSON findings
- Includes sample data and automated tests

## Usage

```bash
npm install
npm test
node src/cli.js sample/auth.log
```

## Example Output

```json
{
  "eventsAnalyzed": 7,
  "findings": [
    {
      "type": "BRUTE_FORCE_PATTERN",
      "severity": "high",
      "ip": "203.0.113.12"
    }
  ]
}
```

## Security Note

This project is defensive. It analyzes existing logs and does not perform scanning, exploitation, or credential attacks.
