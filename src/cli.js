const fs = require("node:fs");
const { analyze } = require("./analyzer");

const [logPath] = process.argv.slice(2);

if (!logPath) {
  console.log("Usage: node src/cli.js <auth.log>");
  process.exit(1);
}

const lines = fs.readFileSync(logPath, "utf8").split(/\r?\n/).filter(Boolean);
const report = analyze(lines);
console.log(JSON.stringify(report, null, 2));
process.exit(report.findings.some((finding) => finding.severity === "high") ? 2 : 0);
