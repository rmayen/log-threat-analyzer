const SIMPLE_LINE = /^(\S+)\s+(\S+)\s+(\S+)\s+(SUCCESS|FAIL)\s+(.+)$/;

const SSH_FAIL = /^(.+?)\s+\S+\s+sshd\[\d+\]:\s+Failed password for(?: invalid user)?\s+(\S+)\s+from\s+(\S+)\s+port\s+\d+/;
const SSH_ACCEPT = /^(.+?)\s+\S+\s+sshd\[\d+\]:\s+Accepted password for\s+(\S+)\s+from\s+(\S+)\s+port\s+\d+/;
const SSH_INVALID = /^(.+?)\s+\S+\s+sshd\[\d+\]:\s+Invalid user\s+(\S+)\s+from\s+(\S+)/;

function parseTimestamp(value) {
  if (!value) return null;
  const direct = Date.parse(value);
  if (!Number.isNaN(direct)) return direct;
  const withYear = Date.parse(`${new Date().getUTCFullYear()} ${value}`);
  return Number.isNaN(withYear) ? null : withYear;
}

function parseLogLine(line) {
  if (!line || !line.trim()) return null;

  const trimmed = line.trim();

  if (trimmed.startsWith("{")) {
    try {
      const obj = JSON.parse(trimmed);
      if (!obj.ip || !obj.user || !obj.outcome) return null;
      return {
        timestamp: obj.timestamp || null,
        timestampMs: parseTimestamp(obj.timestamp),
        ip: obj.ip,
        user: obj.user,
        outcome: String(obj.outcome).toUpperCase(),
        message: obj.message || "",
        source: "json"
      };
    } catch {
      return null;
    }
  }

  const simple = trimmed.match(SIMPLE_LINE);
  if (simple) {
    return {
      timestamp: simple[1],
      timestampMs: parseTimestamp(simple[1]),
      ip: simple[2],
      user: simple[3],
      outcome: simple[4],
      message: simple[5],
      source: "simple"
    };
  }

  const sshAccept = trimmed.match(SSH_ACCEPT);
  if (sshAccept) {
    return {
      timestamp: sshAccept[1],
      timestampMs: parseTimestamp(sshAccept[1]),
      ip: sshAccept[3],
      user: sshAccept[2],
      outcome: "SUCCESS",
      message: "ssh accepted password",
      source: "ssh"
    };
  }

  const sshFail = trimmed.match(SSH_FAIL);
  if (sshFail) {
    return {
      timestamp: sshFail[1],
      timestampMs: parseTimestamp(sshFail[1]),
      ip: sshFail[3],
      user: sshFail[2],
      outcome: "FAIL",
      message: "ssh failed password",
      source: "ssh"
    };
  }

  const sshInvalid = trimmed.match(SSH_INVALID);
  if (sshInvalid) {
    return {
      timestamp: sshInvalid[1],
      timestampMs: parseTimestamp(sshInvalid[1]),
      ip: sshInvalid[3],
      user: sshInvalid[2],
      outcome: "FAIL",
      message: "ssh invalid user",
      source: "ssh"
    };
  }

  return null;
}

function detectWindowedBruteForce(events, ip, threshold, windowMs) {
  const failures = events.filter((event) => event.ip === ip && event.outcome === "FAIL" && event.timestampMs !== null);
  if (failures.length < threshold) return null;

  failures.sort((a, b) => a.timestampMs - b.timestampMs);
  let left = 0;
  let bestCount = 0;
  let bestStart = null;
  let bestEnd = null;

  for (let right = 0; right < failures.length; right++) {
    while (failures[right].timestampMs - failures[left].timestampMs > windowMs) {
      left++;
    }

    const count = right - left + 1;
    if (count > bestCount) {
      bestCount = count;
      bestStart = failures[left].timestamp;
      bestEnd = failures[right].timestamp;
    }
  }

  if (bestCount < threshold) return null;

  return {
    type: "BRUTE_FORCE_PATTERN",
    severity: "high",
    ip,
    count: bestCount,
    detail: `${bestCount} failed logins from ${ip} within window`,
    windowStart: bestStart,
    windowEnd: bestEnd
  };
}

function analyze(lines, options = {}) {
  const failedThreshold = options.failedThreshold || 5;
  const sprayThreshold = options.sprayThreshold || 3;
  const windowSeconds = options.windowSeconds || 600;
  const windowMs = windowSeconds * 1000;

  const parsed = lines.map(parseLogLine);
  const events = parsed.filter(Boolean);
  const malformed = parsed.filter((event) => event === null).length;

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
    const usersAttempted = new Set(failures.map((event) => event.user));
    const successfulUsers = new Set(ipEvents.filter((event) => event.outcome === "SUCCESS").map((event) => event.user));

    const failuresWithTime = failures.filter((event) => event.timestampMs !== null);
    const windowed = failuresWithTime.length > 0 ? detectWindowedBruteForce(ipEvents, ip, failedThreshold, windowMs) : null;

    if (windowed) {
      findings.push(windowed);
    } else if (failuresWithTime.length === 0 && failures.length >= failedThreshold) {
      findings.push({
        type: "BRUTE_FORCE_PATTERN",
        severity: "high",
        ip,
        count: failures.length,
        detail: `${failures.length} failed logins from ${ip}`
      });
    }

    if (usersAttempted.size >= sprayThreshold) {
      findings.push({
        type: "PASSWORD_SPRAY_PATTERN",
        severity: "medium",
        ip,
        count: usersAttempted.size,
        detail: `${ip} attempted logins against ${usersAttempted.size} users: ${[...usersAttempted].slice(0, 5).join(", ")}`
      });
    }

    if (failures.length >= failedThreshold && successfulUsers.size > 0) {
      findings.push({
        type: "SUCCESS_AFTER_FAILURES",
        severity: "high",
        ip,
        count: successfulUsers.size,
        detail: `${ip} had ${failures.length} failures then succeeded as ${[...successfulUsers].join(", ")} — possible credential compromise`
      });
    }
  }

  for (const [user, userEvents] of byUser.entries()) {
    const successfulIps = new Set(userEvents.filter((event) => event.outcome === "SUCCESS").map((event) => event.ip));
    const failingIps = new Set(userEvents.filter((event) => event.outcome === "FAIL").map((event) => event.ip));

    if (successfulIps.size >= 2) {
      findings.push({
        type: "MULTIPLE_SUCCESS_LOCATIONS",
        severity: "low",
        user,
        count: successfulIps.size,
        detail: `${user} had successful logins from ${successfulIps.size} IP addresses: ${[...successfulIps].slice(0, 5).join(", ")}`
      });
    }

    if (failingIps.size >= sprayThreshold) {
      findings.push({
        type: "DISTRIBUTED_TARGETING",
        severity: "medium",
        user,
        count: failingIps.size,
        detail: `${user} was targeted from ${failingIps.size} different IPs — possible credential stuffing target`
      });
    }
  }

  const severityRank = { high: 3, medium: 2, low: 1 };
  findings.sort((a, b) => (severityRank[b.severity] || 0) - (severityRank[a.severity] || 0));

  return {
    eventsAnalyzed: events.length,
    malformedLines: malformed,
    timeRange: events.length > 0
      ? {
          start: events.reduce((min, event) => (event.timestamp && (!min || event.timestamp < min) ? event.timestamp : min), null),
          end: events.reduce((max, event) => (event.timestamp && (!max || event.timestamp > max) ? event.timestamp : max), null)
        }
      : null,
    summary: {
      uniqueIps: byIp.size,
      uniqueUsers: byUser.size,
      successes: events.filter((event) => event.outcome === "SUCCESS").length,
      failures: events.filter((event) => event.outcome === "FAIL").length
    },
    findings
  };
}

module.exports = { analyze, parseLogLine };
