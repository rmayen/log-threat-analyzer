function parseLogLine(line) {
  const match = line.match(/^(\S+)\s+(\S+)\s+(\S+)\s+(SUCCESS|FAIL)\s+(.+)$/);

  if (!match) {
    return null;
  }

  return {
    timestamp: match[1],
    ip: match[2],
    user: match[3],
    outcome: match[4],
    message: match[5]
  };
}

function analyze(lines, options = {}) {
  const failedThreshold = options.failedThreshold || 5;
  const events = lines.map(parseLogLine).filter(Boolean);
  const byIp = new Map();
  const byUser = new Map();

  for (const event of events) {
    if (!byIp.has(event.ip)) byIp.set(event.ip, []);
    if (!byUser.has(event.user)) byUser.set(event.user, []);
    byIp.get(event.ip).push(event);
    byUser.get(event.user).push(event);
  }

  const findings = [];

  for (const [ip, ipEvents] of byIp.entries()) {
    const failures = ipEvents.filter((event) => event.outcome === "FAIL");
    const users = new Set(failures.map((event) => event.user));

    if (failures.length >= failedThreshold) {
      findings.push({
        type: "BRUTE_FORCE_PATTERN",
        severity: "high",
        ip,
        count: failures.length,
        detail: `${failures.length} failed logins from ${ip}`
      });
    }

    if (users.size >= 3) {
      findings.push({
        type: "PASSWORD_SPRAY_PATTERN",
        severity: "medium",
        ip,
        count: users.size,
        detail: `${ip} attempted logins against ${users.size} users`
      });
    }
  }

  for (const [user, userEvents] of byUser.entries()) {
    const successfulIps = new Set(userEvents.filter((event) => event.outcome === "SUCCESS").map((event) => event.ip));

    if (successfulIps.size >= 2) {
      findings.push({
        type: "MULTIPLE_SUCCESS_LOCATIONS",
        severity: "low",
        user,
        count: successfulIps.size,
        detail: `${user} had successful logins from ${successfulIps.size} IP addresses`
      });
    }
  }

  return {
    eventsAnalyzed: events.length,
    findings
  };
}

module.exports = { analyze, parseLogLine };
