#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { sanitize, scan, type ScanResult, type Severity } from "./index.js";

const HELP = `injection-scan - flag prompt-injection attempts in text before an AI agent reads it

Usage:
  injection-scan [files...] [options]
  cat page.html | injection-scan

Reads each file (or stdin when no file is given, or "-") and reports suspicious text.
Exit code 0 when nothing reaches the threshold, 1 when something does, 2 on bad usage.

Options:
  -t, --threshold <level>  Lowest risk that fails: low, medium (default) or high.
  -d, --disable <ids>      Comma-separated rule ids or categories to skip.
      --json               Print results as JSON.
      --sanitize           Print the input with hidden characters, comments and
                           invisible HTML removed instead of scanning it.
  -q, --quiet              Print nothing, only set the exit code.
  -h, --help               Show this help.
  -v, --version            Show the version number.

Examples:
  injection-scan page.html
  curl -s https://example.com | injection-scan --threshold high
  injection-scan --json docs/*.md
`;

const LEVELS = new Set(["low", "medium", "high"]);

class UsageError extends Error {}

function version(): string {
  const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
  return pkg.version;
}

function readInput(path: string): string {
  if (path === "-") return readFileSync(0, "utf8");
  try {
    return readFileSync(path, "utf8");
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw new UsageError(`can't find "${path}".`);
    if (code === "EISDIR") throw new UsageError(`"${path}" is a folder, not a file.`);
    throw new UsageError(`can't read "${path}": ${(error as Error).message}`);
  }
}

function report(name: string, result: ScanResult): string {
  if (result.findings.length === 0) return `${name}: no findings`;
  const lines = [
    `${name}: ${result.risk.toUpperCase()} risk, ${result.findings.length} finding${result.findings.length === 1 ? "" : "s"}`,
  ];
  for (const f of result.findings) {
    const where = `${f.line}:${f.column}`.padEnd(8);
    const hidden = f.hiddenBy ? ` [hidden: ${f.hiddenBy}]` : "";
    lines.push(`  ${where}${f.severity.padEnd(7)}${f.rule}${hidden}`);
    lines.push(`          "${f.excerpt}"`);
    lines.push(`          ${f.message}`);
  }
  return lines.join("\n");
}

function run(argv: readonly string[]): number {
  let parsed;
  try {
    parsed = parseArgs({
      args: [...argv],
      allowPositionals: true,
      options: {
        threshold: { type: "string", short: "t" },
        disable: { type: "string", short: "d" },
        json: { type: "boolean" },
        sanitize: { type: "boolean" },
        quiet: { type: "boolean", short: "q" },
        help: { type: "boolean", short: "h" },
        version: { type: "boolean", short: "v" },
      },
    });
  } catch (error) {
    throw new UsageError((error as Error).message);
  }
  const { values, positionals } = parsed;
  if (values.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (values.version) {
    process.stdout.write(`${version()}\n`);
    return 0;
  }
  const threshold = values.threshold ?? "medium";
  if (!LEVELS.has(threshold)) throw new UsageError(`--threshold must be low, medium or high, not "${threshold}".`);
  const disable = (values.disable ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const files = positionals.length > 0 ? positionals : ["-"];
  if (files.includes("-") && process.stdin.isTTY) {
    process.stdout.write(HELP);
    return 2;
  }

  if (values.sanitize) {
    for (const file of files) process.stdout.write(sanitize(readInput(file)));
    return 0;
  }

  let failed = false;
  const results: { file: string; result: ScanResult }[] = [];
  for (const file of files) {
    const result = scan(readInput(file), { threshold: threshold as Severity, disable });
    if (result.flagged) failed = true;
    results.push({ file: file === "-" ? "stdin" : file, result });
  }
  if (values.json) {
    const out = results.length === 1 && positionals.length <= 1 ? results[0]!.result : results;
    process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
  } else if (!values.quiet) {
    process.stdout.write(`${results.map((r) => report(r.file, r.result)).join("\n\n")}\n`);
  }
  return failed ? 1 : 0;
}

try {
  process.exitCode = run(process.argv.slice(2));
} catch (error) {
  if (error instanceof UsageError) {
    process.stderr.write(`injection-scan: ${error.message}\nRun "injection-scan --help" for usage.\n`);
    process.exitCode = 2;
  } else {
    throw error;
  }
}
