const fs = require("node:fs");
const { analyze } = require("./analyzer");

function parseArgs(argv) {
  const args = {
    files: [],
    format: "json",
    output: null,
    failedThreshold: 5,
    sprayThreshold: 3,
    windowSeconds: 600
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (arg === "--format" || arg === "-f") {
      args.format = argv[++i];
    } else if (arg === "--output" || arg === "-o") {
      args.output = argv[++i];
    } else if (arg === "--threshold") {
      args.failedThreshold = Number(argv[++i]);
    } else if (arg === "--spray-threshold") {
      args.sprayThreshold = Number(argv[++i]);
    } else if (arg === "--window") {
      args.windowSeconds = Number(argv[++i]);
    } else if (arg === "--help" || arg === "-h") {
      args.help = true;
    } else if (!arg.startsWith("--")) {
      args.files.push(arg);
    }
  }

  return args;
}

function printHelp() {
  console.log(`Usage: node src/cli.js [options] <log file> [<log file>...]

Options:
  --format, -f <fmt>     Output format: json (default) or text
  --output, -o <path>    Write report to file instead of stdout
  --threshold <n>        Failed login count to flag brute force (default 5)
  --spray-threshold <n>  Distinct usernames per IP to flag spray (default 3)
  --window <seconds>     Time window for brute force detection (default 600)
  --help, -h             Show this help

Supported log formats:
  - simple:  "<timestamp> <ip> <user> SUCCESS|FAIL <message>"
  - sshd:    standard /var/log/auth.log lines
  - json:    one JSON object per line with ip, user, outcome, timestamp

Examples:
  node src/cli.js sample/auth.log
  node src/cli.js --format text --threshold 3 sample/auth.log
  node src/cli.js --output report.json sample/auth.log sample/sshd.log
`);
}

function formatText(report) {
  const lines = [];
  lines.push(`events analyzed: ${report.eventsAnalyzed}`);

  if (report.malformedLines > 0) {
    lines.push(`malformed lines skipped: ${report.malformedLines}`);
  }

  if (report.timeRange) {
    lines.push(`time range: ${report.timeRange.start} → ${report.timeRange.end}`);
  }

  lines.push(`unique ips: ${report.summary.uniqueIps}  unique users: ${report.summary.uniqueUsers}`);
  lines.push(`successes: ${report.summary.successes}  failures: ${report.summary.failures}`);

  if (report.findings.length === 0) {
    lines.push("");
    lines.push("no suspicious patterns detected");
    return lines.join("\n");
  }

  lines.push("");
  lines.push(`findings (${report.findings.length}):`);

  for (const finding of report.findings) {
    const tag = `[${finding.severity.toUpperCase()}]`.padEnd(9);
    lines.push(`  ${tag} ${finding.type}`);
    lines.push(`           ${finding.detail}`);
  }

  return lines.join("\n");
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help || args.files.length === 0) {
    printHelp();
    process.exit(args.help ? 0 : 1);
  }

  const lines = [];
  for (const file of args.files) {
    const content = fs.readFileSync(file, "utf8");
    lines.push(...content.split(/\r?\n/).filter(Boolean));
  }

  const report = analyze(lines, {
    failedThreshold: args.failedThreshold,
    sprayThreshold: args.sprayThreshold,
    windowSeconds: args.windowSeconds
  });

  const output = args.format === "text" ? formatText(report) : JSON.stringify(report, null, 2);

  if (args.output) {
    fs.writeFileSync(args.output, output);
    console.log(`Wrote report to ${args.output}`);
  } else {
    console.log(output);
  }

  process.exit(report.findings.some((finding) => finding.severity === "high") ? 2 : 0);
}

main();
