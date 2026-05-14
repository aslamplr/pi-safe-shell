/**
 * pi-safe-shell — Protect your production assets from dangerous bash commands.
 *
 * Four operating modes:
 *   block     (default) — All bash calls are blocked. Agent must use Read/Write/Edit/Grep/Find.
 *   ask       — User is prompted for each bash call. Can allow once or for the session.
 *   whitelist — Only commands matching curated safe patterns pass through.
 *   yolo      — Allow everything except denylist items. Use with extreme caution.
 *
 * Three layers of config (highest priority first):
 *   1. Session state  (temp approvals granted during this chat)
 *   2. Project config  (.pi/pi-safe-shell.json)
 *   3. Global config   (~/.pi/agent/extensions/pi-safe-shell/config.json)
 *
 * Safe replacement tools registered:
 *   - run_tests     — Run tests with capped output
 *   - git_status    — Git status (porcelain + branch)
 *   - list_files    — List filenames in a directory (names only, no contents)
 *
 * Usage:
 *   pi -e ./pi-safe-shell/index.ts
 *   # OR copy to ~/.pi/agent/extensions/pi-safe-shell/index.ts (auto-discovered)
 *
 * Commands:
 *   /safe-shell                     — Show current mode + summary
 *   /safe-shell mode block|ask|whitelist|yolo  — Switch mode
 *   /safe-shell allow <command> [--project]  — Add approval (--project persists to .pi/pi-safe-shell.json)
 *   /safe-shell deny <command> [--project]   — Remove approval (--project removes from project whitelist)
 */

import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import { Text } from "@earendil-works/pi-tui";
import { StringEnum } from "@earendil-works/pi-ai";
import { Type } from "typebox";
import { execFile } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { homedir } from "node:os";
import { promisify } from "node:util";
import { initParser, analyzeCommand, scoreCommand, isParserInitialized } from "./src/ast-analyzer";
import { analyzeCode, formatCodeAnalysis, CodeAnalysis } from "./src/code-analyzer";

// ============================================================
// Types
// ============================================================

type Mode = "block" | "ask" | "whitelist" | "yolo";

interface GlobalConfig {
  defaultMode: Mode;
  whitelist: string[];
  denylist: string[];
  rejectCompoundOperators: boolean;
  testCommand: string;
  testCommandArgs: string[];
  testTimeout: number;
}

interface SessionState {
  mode?: Mode;
  tempApprovals: string[];
}

// ============================================================
// Constants
// ============================================================

const SESSION_STATE_TYPE = "pi-safe-shell-state";

const GLOBAL_CONFIG_DIR = join(homedir(), ".pi", "agent", "extensions", "pi-safe-shell");
const GLOBAL_CONFIG_PATH = join(GLOBAL_CONFIG_DIR, "config.json");

const SHELL_OPERATORS = /(&&|\|\||\||;|`|\$\(|>|<)/;

// Patterns that indicate code is executing shell commands via child_process / subprocess
const SHELL_EXEC_PATTERNS: { pattern: RegExp; label: string }[] = [
  // Node.js patterns
  { pattern: /execSync\s*\(/, label: "execSync" },
  { pattern: /execFileSync\s*\(/, label: "execFileSync" },
  { pattern: /[\.\w]*exec\s*\(/, label: "exec" },
  { pattern: /[\.\w]*spawn(?:Sync)?\s*\(/, label: "spawn/spawnSync" },
  { pattern: /child_process/, label: "child_process" },
  { pattern: /shell\s*:\s*true/, label: "shell:true" },
  { pattern: /fork\s*\(/, label: "fork" },
  // Python patterns
  { pattern: /os\.system\s*\(/, label: "os.system" },
  { pattern: /os\.popen\s*\(/, label: "os.popen" },
  { pattern: /subprocess\.(?:run|call|check_output|Popen|check_call)\s*\(/, label: "subprocess" },
  { pattern: /shell\s*=\s*True/, label: "subprocess(shell=True)" },
];

// Try to extract a shell command string from JS/Python child_process calls
function tryExtractShellCommand(code: string): string | null {
  // Match execSync('command'), os.system('command'), subprocess.run('command'), etc.
  const execMatch = code.match(/[\.\w]*(?:execSync|exec|execFileSync|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen|check_call))\s*\(\s*([`"'])((?:[^`"'\\]|\\.)*?)\1/);
  if (execMatch) return execMatch[2];
  // Match spawn('command'), spawnSync('command'), fork('command')
  const spawnMatch = code.match(/[\.\w]*(?:spawn|spawnSync|fork)\s*\(\s*([`"'])((?:[^`"'\\]|\\.)*?)\1/);
  if (spawnMatch) return spawnMatch[2];
  return null;
}

const DEFAULT_CONFIG: GlobalConfig = {
  defaultMode: "block",
  whitelist: [
    "^pwd$",
    "^ls(\\s+-[laA]+)*(\\s+[\\w./\\-]+)?$",
    "^cat\\s+[\\w./\\-]+\\.(md|txt|json|ya?ml|toml|env)$",
    "^(npm|pnpm|yarn)\\s+(test|run\\s+\\w+|start)$",
    "^npx\\s+[\\w@./\\-]+(\\s+[\\w./\\-]+)*$",
    "^uv\\s+run\\s+(pytest|ruff)\\b",
    "^git\\s+(status|log\\s+--oneline|diff|branch|show|add|-A|commit|push|pull|stash)\\b",
    "^node\\s+--version$",
    "^python3?\\s+--version$",
    "^make\\s+\\w*$",
    "^just\\s+\\w*$",
    "^which\\s+[\\w./\\-]+$",
    "^echo\\s+.+$",
    "^date$",
  ],
  denylist: [
    "rm -rf /",
    "rm -rf ~",
    "rm -rf .",
    "sudo",
    "> /dev",
    "mkfs",
    "dd if=",
    ":(){ :|:& };:",
    "chmod 777",
    "chown -R",
  ],
  rejectCompoundOperators: true,
  testCommand: "uv",
  testCommandArgs: ["run", "pytest", "-q"],
  testTimeout: 120_000,
};

const execP = promisify(execFile);

// ============================================================
// Config helpers
// ============================================================

function loadGlobalConfig(): GlobalConfig {
  try {
    if (existsSync(GLOBAL_CONFIG_PATH)) {
      const raw = readFileSync(GLOBAL_CONFIG_PATH, "utf-8");
      const user = JSON.parse(raw);
      return { ...DEFAULT_CONFIG, ...user };
    }
  } catch {
    // fall through to default
  }
  return { ...DEFAULT_CONFIG };
}

function loadProjectConfig(cwd: string): Partial<GlobalConfig> | null {
  try {
    const path = join(cwd, ".pi", "pi-safe-shell.json");
    if (existsSync(path)) {
      return JSON.parse(readFileSync(path, "utf-8"));
    }
  } catch {
    // ignore corrupt/missing project config
  }
  return null;
}

function mergeConfigs(
  global: GlobalConfig,
  project: Partial<GlobalConfig> | null,
): GlobalConfig {
  if (!project) return global;
  return {
    ...global,
    ...project,
    whitelist: project.whitelist ?? global.whitelist,
    denylist: project.denylist ?? global.denylist,
    testCommand: project.testCommand ?? global.testCommand,
    testCommandArgs: project.testCommandArgs ?? global.testCommandArgs,
    testTimeout: project.testTimeout ?? global.testTimeout,
  };
}

function ensureGlobalConfigExists(): void {
  try {
    if (!existsSync(GLOBAL_CONFIG_DIR)) {
      mkdirSync(GLOBAL_CONFIG_DIR, { recursive: true });
    }
    if (!existsSync(GLOBAL_CONFIG_PATH)) {
      writeFileSync(GLOBAL_CONFIG_PATH, JSON.stringify(DEFAULT_CONFIG, null, 2) + "\n", "utf-8");
    }
  } catch {
    // filesystem errors are non-fatal; extension works with defaults
  }
}

// ============================================================
// Shell Command Analysis Helpers
// ============================================================

/**
 * Format AST analysis result into user-friendly block message
 */
function formatShellBlockMessage(analysis: ReturnType<typeof analyzeCommand>, riskResult: ReturnType<typeof scoreCommand>, command: string): string {
  const emoji = riskResult.level === "critical" ? "🔒" : "⚠️";
  
  let message = `${emoji} Dangerous Shell Command Detected (${riskResult.level.toUpperCase()}: ${riskResult.score}/100)\n\n`;
  message += `Command: ${command}\n\n`;
  
  // Show intent classification
  if (analysis.intent && analysis.intent.length > 0) {
    const intentLabels = analysis.intent.map(i => i.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())).join(', ');
    message += `Intent: ${intentLabels}\n\n`;
  }
  
  // Show risk factors
  if (riskResult.riskFactors && riskResult.riskFactors.length > 0) {
    message += `Risk Factors:\n`;
    for (const factor of riskResult.riskFactors) {
      message += `  • ${formatRiskFactor(factor)}\n`;
    }
    message += "\n";
  }
  
  // Show reasons for the score
  if (riskResult.reasons && riskResult.reasons.length > 0) {
    message += `Detection Reasons:\n`;
    for (const reason of riskResult.reasons.slice(0, 5)) { // Limit to top 5
      message += `  • ${reason}\n`;
    }
    message += "\n";
  }
  
  message += "Why This Is Dangerous:\n";
  message += `  ${getShellDangerExplanation(riskResult)}\n`;
  
  message += "\nSafer Alternatives:\n";
  const alternatives = getShellSaferAlternatives(riskResult);
  for (const alt of alternatives) {
    message += `  • ${alt}\n`;
  }
  
  message += "\nOverride:\n";
  message += "  Use the safe_shell_approve tool to allow this command for this session.\n";
  
  return message;
}

/**
 * Format risk factor into human-readable label
 */
function formatRiskFactor(factor: string): string {
  return factor
    .replace(/_/g, ' ')
    .replace(/\b\w/g, l => l.toUpperCase());
}

/**
 * Get explanation of why shell command is dangerous
 */
function getShellDangerExplanation(riskResult: ReturnType<typeof scoreCommand>): string {
  const factors = riskResult.riskFactors || [];
  
  if (factors.includes("system_path")) {
    return "This command targets system directories (/etc, /usr, /bin) which are critical for OS operation. " +
           "Modifying or deleting these files could render the system unbootable.";
  }
  if (factors.includes("home_path")) {
    return "This command targets user home directories which contain personal data, credentials, and configurations. " +
           "Destructive operations here could result in permanent data loss.";
  }
  if (factors.includes("recursive_operation")) {
    return "This command uses recursive flags (-r, -R, --recursive) which can delete or modify entire directory trees. " +
           "Combined with destructive operations, this amplifies the potential damage.";
  }
  if (factors.includes("force_flag")) {
    return "This command uses force flags (-f, --force) which bypass confirmation prompts and error handling. " +
           "This prevents safety checks and can lead to unintended consequences.";
  }
  if (factors.includes("remote_code_execution")) {
    return "This command downloads and executes code from remote sources (curl|bash, wget|bash). " +
           "This is a common attack vector for malware and supply chain compromise.";
  }
  if (factors.includes("data_exfiltration")) {
    return "This command sends data to external servers, potentially exfiltrating sensitive information. " +
           "Combined with file read operations, this is a data breach pattern.";
  }
  if (factors.includes("destructive_operation")) {
    return "This command performs destructive operations (delete, format, overwrite) that permanently modify or destroy data. " +
           "These operations are often irreversible.";
  }
  if (factors.includes("privilege_escalation")) {
    return "This command uses elevated privileges (sudo, su) to bypass permission restrictions. " +
           "Combined with destructive operations, this can damage system integrity.";
  }
  if (factors.includes("inline_code_execution")) {
    return "This command executes code via interpreters (bash -c, python -c, eval). " +
           "This bypasses shell analysis and can perform arbitrary operations.";
  }
  if (factors.includes("obfuscated_code_execution")) {
    return "This command uses obfuscation (base64, encoding) to hide its true intent. " +
           "Obfuscation is commonly used to evade security analysis.";
  }
  if (factors.includes("chained_command")) {
    return "This command chains multiple operations together (&&, ||, ;). " +
           "Each command in the chain is executed, potentially compounding risks.";
  }
  if (factors.includes("fork_bomb")) {
    return "This command creates a fork bomb that spawns infinite processes. " +
           "This will exhaust system resources and crash the machine.";
  }
  
  return "This command contains patterns that may be dangerous depending on context and usage. " +
         "Review the risk factors and detection reasons above.";
}

/**
 * Get safer alternative suggestions for shell commands
 */
function getShellSaferAlternatives(riskResult: ReturnType<typeof scoreCommand>): string[] {
  const alternatives: string[] = [];
  const factors = riskResult.riskFactors || [];
  
  if (factors.includes("system_path")) {
    alternatives.push("Use project-relative paths (./build, ./dist) instead of absolute system paths");
    alternatives.push("Add path validation to ensure target is within project directory");
  }
  if (factors.includes("home_path")) {
    alternatives.push("Use temporary directories (/tmp, ./tmp) for test data");
    alternatives.push("Avoid operations in user home directories unless absolutely necessary");
  }
  if (factors.includes("recursive_operation")) {
    alternatives.push("Use non-recursive operations when possible (rm file instead of rm -r dir)");
    alternatives.push("Preview with ls -la before destructive recursive operations");
    alternatives.push("Use dry-run flags (--dry-run, -n) when available");
  }
  if (factors.includes("force_flag")) {
    alternatives.push("Remove -f flag to allow confirmation prompts");
    alternatives.push("Use interactive mode (-i) for destructive operations");
  }
  if (factors.includes("remote_code_execution")) {
    alternatives.push("Download code first, review it, then execute separately");
    alternatives.push("Use package managers (npm, pip, apt) instead of curl|bash");
    alternatives.push("Verify checksums and signatures before executing remote code");
  }
  if (factors.includes("data_exfiltration")) {
    alternatives.push("Avoid sending sensitive data (SSH keys, credentials, .env files) over network");
    alternatives.push("Use encrypted connections (HTTPS, SSH) for all network operations");
    alternatives.push("Validate destination URLs against allowlist");
  }
  if (factors.includes("destructive_operation")) {
    alternatives.push("Use version control (git) to track changes before destructive operations");
    alternatives.push("Create backups before destructive operations");
    alternatives.push("Use trash/rm-trash instead of rm for reversible deletion");
  }
  if (factors.includes("privilege_escalation")) {
    alternatives.push("Run without sudo if possible (check file permissions)");
    alternatives.push("Use specific sudo commands instead of sudo -i or sudo su");
    alternatives.push("Configure sudoers for specific commands without password");
  }
  if (factors.includes("inline_code_execution")) {
    alternatives.push("Write code to a file and execute the file instead of inline");
    alternatives.push("Use shell scripts for complex operations (easier to review and audit)");
  }
  if (factors.includes("chained_command")) {
    alternatives.push("Break command chains into separate, reviewable steps");
    alternatives.push("Execute each command individually and verify results");
  }
  
  if (alternatives.length === 0) {
    alternatives.push("Review command intent and ensure it matches expected behavior");
    alternatives.push("Consider using safer built-in tools (run_tests, git_status, list_files)");
  }
  
  return alternatives;
}

// ============================================================
// Code Analysis Helpers
// ============================================================

/**
 * Format code analysis result into user-friendly block message
 */
function formatCodeBlockMessage(analysis: CodeAnalysis, filePath: string): string {
  const emoji = analysis.level === "critical" ? "🔒" : "⚠️";
  
  let message = `${emoji} Dangerous Code Detected (${analysis.level.toUpperCase()}: ${analysis.score}/100)\n\n`;
  message += `Language: ${analysis.language}\n`;
  if (filePath) {
    message += `File: ${filePath}\n`;
  }
  message += "\n";
  
  if (analysis.obfuscationDetected) {
    message += `⚠️ Obfuscation Detected: ${analysis.obfuscationPatterns.join(", ")}\n\n`;
  }
  
  message += `Dangerous API Calls (${analysis.dangerousCalls.length}):\n`;
  for (const call of analysis.dangerousCalls) {
    message += `  • ${call.api} (${call.severity}) at ${call.location}\n`;
    if (call.argument) {
      const argPreview = call.argument.length > 60 
        ? call.argument.slice(0, 60) + "..." 
        : call.argument;
      message += `    Argument: ${argPreview}\n`;
    }
    if (call.lineContent) {
      const linePreview = call.lineContent.length > 80 
        ? call.lineContent.slice(0, 80) + "..." 
        : call.lineContent;
      message += `    Code: ${linePreview}\n`;
    }
  }
  
  message += "\nRisk Factors: " + analysis.riskFactors.join(", ") + "\n";
  
  message += "\nWhy This Is Dangerous:\n";
  message += `  ${getDangerousCodeExplanation(analysis)}\n`;
  
  message += "\nSafer Alternatives:\n";
  const alternatives = getSaferCodeAlternatives(analysis);
  for (const alt of alternatives) {
    message += `  • ${alt}\n`;
  }
  
  message += "\nOverride:\n";
  message += "  Use the safe_shell_approve tool to allow this code for this session.\n";
  
  return message;
}

/**
 * Get explanation of why detected code is dangerous
 */
function getDangerousCodeExplanation(analysis: CodeAnalysis): string {
  const categories = analysis.riskFactors;
  
  if (categories.includes("fs_destructive")) {
    return "This code performs destructive file system operations (delete, remove, truncate). " +
           "If targeting system or user directories, this could result in permanent data loss.";
  }
  if (categories.includes("shell_exec")) {
    return "This code executes shell commands, bypassing shell analysis and security gates. " +
           "Shell execution can perform any operation with the user's permissions.";
  }
  if (categories.includes("network")) {
    return "This code performs network operations that could exfiltrate sensitive data to external servers. " +
           "Combined with file read operations, this is a common data exfiltration pattern.";
  }
  if (categories.includes("code_exec")) {
    return "This code dynamically executes code, which is a critical security risk. " +
           "If the executed code comes from user input, this allows arbitrary code execution.";
  }
  if (analysis.obfuscationDetected) {
    return "This code uses obfuscation techniques (encoding, string manipulation) to hide its intent. " +
           "Obfuscation is commonly used to bypass security analysis.";
  }
  
  return "This code contains patterns that may be dangerous depending on context and usage.";
}

/**
 * Get safer alternative suggestions
 */
function getSaferCodeAlternatives(analysis: CodeAnalysis): string[] {
  const alternatives: string[] = [];
  const categories = analysis.riskFactors;
  
  if (categories.includes("fs_destructive")) {
    alternatives.push("Use project-relative paths (./build, ./dist) instead of absolute paths");
    alternatives.push("Add path validation to ensure target is within project directory");
    alternatives.push("Use dry-run or preview before destructive operations");
  }
  if (categories.includes("shell_exec")) {
    alternatives.push("Use native APIs instead of shell execution (e.g., fs.rm instead of 'rm -rf')");
    alternatives.push("Avoid shell=true in child_process APIs");
    alternatives.push("Use spawn with explicit arguments array instead of shell strings");
  }
  if (categories.includes("network")) {
    alternatives.push("Validate URLs against allowlist before making requests");
    alternatives.push("Avoid sending sensitive data (SSH keys, credentials) over network");
    alternatives.push("Use encrypted connections (HTTPS) for all network operations");
  }
  if (categories.includes("code_exec")) {
    alternatives.push("Avoid eval/exec with any form of user input");
    alternatives.push("Use safer alternatives (JSON.parse instead of eval for data)");
    alternatives.push("If dynamic code is required, use sandboxed environments");
  }
  if (analysis.obfuscationDetected) {
    alternatives.push("Write code explicitly without encoding or string manipulation");
    alternatives.push("Use clear, readable code that security tools can analyze");
  }
  
  if (alternatives.length === 0) {
    alternatives.push("Review code intent and ensure it matches expected behavior");
  }
  
  return alternatives;
}

// ============================================================
// Session state helpers
// ============================================================

const MODE_LABELS: Record<Mode, string> = {
  block: "🔒 Block",
  ask: "❓ Ask",
  whitelist: "🔓 Whitelist",
  yolo: "🚀 YOLO",
};

// State management functions (defined early for use in checkShellCommand)
let _pi: ExtensionAPI | null = null;
let _sessionMode: Mode | undefined;
let _tempApprovals: string[] = [];

function setSessionState(pi: ExtensionAPI, mode: Mode | undefined, tempApprovals: string[]) {
  _pi = pi;
  _sessionMode = mode;
  _tempApprovals = tempApprovals;
}

function persistState(): void {
  if (!_pi) return;
  const state: SessionState = {
    mode: _sessionMode,
    tempApprovals: [..._tempApprovals],
  };
  _pi.appendEntry(SESSION_STATE_TYPE, state);
}

function compilePatterns(patterns: string[]): RegExp[] {
  return patterns.map((p) => {
    try {
      return new RegExp(p);
    } catch {
      // Invalid regex pattern — skip it silently
      return /(?!)/; // never-matches pattern
    }
  });
}

function commandMatchesAny(command: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(command));
}

/**
 * Tokenize a command string: split by whitespace and strip surrounding quotes.
 */
function tokenize(s: string): string[] {
  return s
    .trim()
    .split(/\s+/)
    .map((t) => {
      if (t.length >= 2) {
        const first = t[0];
        const last = t[t.length - 1];
        if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
          return t.slice(1, -1);
        }
      }
      return t;
    });
}

/**
 * Check if any denylist pattern matches a contiguous subsequence of command tokens.
 * Uses exact token-for-token comparison after quote stripping, so:
 *   "rm -rf /"    blocks "rm -rf /"  but NOT "rm -rf /tmp"
 *   "sudo"        blocks "sudo apt"  but NOT "--with-sudo-support"
 *   "rm \"-rf\" /" blocks "rm -rf /"  after quote normalization
 */
function commandTokenMatch(command: string, patterns: string[]): boolean {
  const cmdTokens = tokenize(command);
  if (cmdTokens.length === 0) return false;

  return patterns.some((pattern) => {
    const patTokens = tokenize(pattern);
    if (patTokens.length === 0 || patTokens.length > cmdTokens.length) return false;

    // Slide over command tokens looking for a contiguous match
    for (let i = 0; i <= cmdTokens.length - patTokens.length; i++) {
      let matches = true;
      for (let j = 0; j < patTokens.length; j++) {
        if (cmdTokens[i + j] !== patTokens[j]) {
          matches = false;
          break;
        }
      }
      if (matches) return true;
    }
    return false;
  });
}

/**
 * Check a single shell command against denylist, temp approvals, and mode policy.
 * Returns undefined (allow) or { block: true, reason: string } (block).
 */
async function checkShellCommand(
  command: string,
  merged: GlobalConfig,
  mode: Mode,
  toolName: string,
  ctx: ExtensionContext,
  tempApprovals: string[],
  reloadProjectConfig?: (cwd: string) => void,
): Promise<{ block: boolean; reason?: string } | undefined> {
  const mergedConfig = merged;

  // --- 1. Denylist check (always applies) ---
  if (commandTokenMatch(command, mergedConfig.denylist)) {
    return {
      block: true,
      reason: `denylist matched.\n  Tool: ${toolName}\n  Command: ${truncate(command, 200)}\n  Blocked by rule.`,
    };
  }

  // --- 2. Session temp approvals check (always applies) ---
  if (tempApprovals.includes(command)) {
    return undefined; // Allow
  }

  // --- 2b. AST-based risk analysis (logging only for Phase 1) ---
  if (isParserInitialized()) {
    try {
      const astAnalysis = analyzeCommand(command);
      const riskResult = scoreCommand(astAnalysis);
      
      // Phase 3: Log all analysis, block based on risk level
      console.log(`[pi-safe-shell AST] ${command}`);
      console.log(`  Score: ${riskResult.score} (${riskResult.level})`);
      console.log(`  Reasons: ${riskResult.reasons.join(', ')}`);
      console.log(`  Risk factors: ${riskResult.riskFactors.join(', ')}`);
      
      // Phase 3: Block critical risks, require confirmation for danger
      if (riskResult.level === 'critical') {
        return {
          block: true,
          reason: formatShellBlockMessage(astAnalysis, riskResult, command),
        };
      }
      
      if (riskResult.level === 'danger' && mode !== 'yolo') {
        // In 'ask' mode, require confirmation for danger-level commands
        if (mode === 'ask') {
          return {
            block: true,
            reason: formatShellBlockMessage(astAnalysis, riskResult, command),
          };
        }
      }
      //   };
      // }
    } catch (err) {
      // AST analysis failed - log but don't block
      console.error('[pi-safe-shell AST] Analysis failed:', err);
    }
  }

  // --- 3. Mode check ---
  switch (mode) {
    case "block": {
      return {
        block: true,
        reason:
          `bash is disabled by policy.\n` +
          `  Tool: ${toolName}\n` +
          `  Command: ${truncate(command, 200)}\n\n` +
          `  Use one of the available built-in tools (Read, Write, Edit, Grep, Find)\n` +
          `  or a registered safe tool (run_tests, git_status, list_files).\n\n` +
          `  To allow this command WITHOUT using bash:\n` +
          `    → Use the safe_shell_approve tool with action="allow" and command="${truncate(command, 80)}"\n` +
          `    → Or run: /safe-shell allow ${truncate(command, 100)}`,
      };
    }

    case "whitelist": {
      // Reject compound shell operators before checking whitelist
      if (mergedConfig.rejectCompoundOperators && SHELL_OPERATORS.test(command)) {
        return {
          block: true,
          reason:
            `compound/chained command rejected.\n` +
            `  Tool: ${toolName}\n` +
            `  Command: ${truncate(command, 200)}\n` +
            `  Compound operators (&&, ||, ;, |, \`, \$(\), <, >) are not allowed.`,
        };
      }

      const whitelistPatterns = compilePatterns(mergedConfig.whitelist);
      if (commandMatchesAny(command, whitelistPatterns)) {
        return undefined; // Allow
      }

      return {
        block: true,
        reason:
          `command not in allowlist.\n` +
          `  Tool: ${toolName}\n` +
          `  Command: ${truncate(command, 200)}\n\n` +
          `  To allow this command:\n` +
          `    → Use the safe_shell_approve tool with action="allow" and command="${truncate(command, 80)}"\n` +
          `    → Or run: /safe-shell allow ${truncate(command, 100)}`,
      };
    }

    case "ask": {
      if (!ctx.hasUI) {
        return {
          block: true,
          reason:
            `command blocked (no UI for confirmation).\n` +
            `  Tool: ${toolName}\n` +
            `  Command: ${truncate(command, 200)}`,
        };
      }

      const choice = await ctx.ui.select(
        `🐚 pi-safe-shell: allow this command?\n\n  Tool: ${toolName}\n  ${truncate(command, 300)}`,
        ["Allow Once", "Allow Always", "Allow for Project", "Deny"],
      );

      if (!choice || choice === "Deny") {
        return { block: true, reason: "command blocked by user." };
      }

      if (choice === "Allow Always") {
        tempApprovals.push(command);
        persistState();
      }

      if (choice === "Allow for Project") {
        tempApprovals.push(command);
        persistState();
        if (persistAllowToProject(ctx.cwd, command) && reloadProjectConfig) {
          reloadProjectConfig(ctx.cwd);
        }
      }

      return undefined; // Allow
    }

    case "yolo": {
      // YOLO mode: allow everything except denylist items (checked above)
      // No whitelist check, no user prompt
      return undefined;
    }

    default:
      return {
        block: true,
        reason:
          `invalid mode "${mode}". Defaulting to block.\n` +
          `  Tool: ${toolName}\n` +
          `  Command: ${truncate(command, 200)}`,
      };
  }
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 3) + "...";
}

/** Persist a command to the project whitelist file and return true if added (not duplicate). */
function persistAllowToProject(cwd: string, command: string): boolean {
  const projectConfigPath = join(cwd, ".pi", "pi-safe-shell.json");
  let projectCfg: any = {};
  if (existsSync(projectConfigPath)) {
    try {
      projectCfg = JSON.parse(readFileSync(projectConfigPath, "utf-8"));
    } catch {
      projectCfg = {};
    }
  }
  if (!Array.isArray(projectCfg.whitelist)) {
    projectCfg.whitelist = [];
  }
  if (projectCfg.whitelist.includes(command)) {
    return false;
  }
  projectCfg.whitelist.push(command);
  const dir = join(cwd, ".pi");
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  writeFileSync(projectConfigPath, JSON.stringify(projectCfg, null, 2), "utf-8");
  return true;
}

// ============================================================
// Extension entry
// ============================================================

export default function (pi: ExtensionAPI) {
  // ---- State (in-memory, reconstructed on session events) ----
  let sessionMode: Mode | undefined;
  let tempApprovals: string[] = [];

  // Sync state to module-level variables for checkShellCommand
  function syncState() {
    setSessionState(pi, sessionMode, tempApprovals);
  }

  // ---- Config (loaded once on startup, cached) ----
  let globalConfig: GlobalConfig = { ...DEFAULT_CONFIG };
  let projectConfig: Partial<GlobalConfig> | null = null;

  // Resolve current effective mode
  function effectiveMode(): Mode {
    return sessionMode ?? projectConfig?.defaultMode ?? globalConfig.defaultMode;
  }

  // Rebuild session state from persisted entries
  function rebuildState(_ctx: ExtensionContext): void {
    sessionMode = undefined;
    tempApprovals = [];

    // Scan all entries for the latest pi-safe-shell state entry
    let found: SessionState | undefined;
    for (const entry of _ctx.sessionManager.getEntries()) {
      if (entry.type === "custom" && entry.customType === SESSION_STATE_TYPE) {
        const raw = entry.data as unknown;
        if (raw && typeof raw === "object" && "tempApprovals" in (raw as Record<string, unknown>)) {
          const data = raw as SessionState;
          if (Array.isArray(data.tempApprovals)) found = data;
        }
      }
    }
    if (found) {
      if (found.mode && ["block", "ask", "whitelist", "yolo"].includes(found.mode)) {
        sessionMode = found.mode;
      }
      if (Array.isArray(found.tempApprovals)) {
        tempApprovals = [...found.tempApprovals];
      }
    }

    // Sync to module-level for checkShellCommand
    syncState();
  }

  // ---- Event: session_start ----
  pi.on("session_start", async (_event, ctx) => {
    // Ensure global config file exists
    ensureGlobalConfigExists();

    // Load configs
    globalConfig = loadGlobalConfig();
    projectConfig = loadProjectConfig(ctx.cwd);

    // Check for corrupt config files and notify user
    if (existsSync(GLOBAL_CONFIG_PATH)) {
      try {
        JSON.parse(readFileSync(GLOBAL_CONFIG_PATH, "utf-8"));
      } catch {
        ctx.ui.notify(
          `pi-safe-shell: corrupt global config at ${GLOBAL_CONFIG_PATH}. Using defaults.`,
          "warning",
        );
      }
    }
    const projectConfigPath = join(ctx.cwd, ".pi", "pi-safe-shell.json");
    if (existsSync(projectConfigPath)) {
      try {
        JSON.parse(readFileSync(projectConfigPath, "utf-8"));
      } catch {
        ctx.ui.notify(
          `pi-safe-shell: corrupt project config at ${projectConfigPath}. Using defaults.`,
          "warning",
        );
      }
    }

    // Initialize AST parser
    try {
      await initParser();
    } catch (err) {
      ctx.ui.notify(
        `pi-safe-shell: AST parser initialization failed. AST analysis disabled.`,
        "warning",
      );
    }

    // Rebuild session state
    rebuildState(ctx);
  });

  // ---- Event: before_agent_start — inject mode into system prompt ----
  pi.on("before_agent_start", async (_event, ctx) => {
    const mode = effectiveMode();
    const modeLabel = MODE_LABELS[mode];
    const approvals = tempApprovals.length;

    const modeHint =
      `You are operating in ${modeLabel} bash security mode. ` +
      (mode === "block"
        ? "All bash commands are blocked. Use the available built-in tools (Read, Write, Edit, Grep, Find) or registered safe tools (run_tests, git_status, list_files)."
        : mode === "ask"
          ? `Each bash command requires user confirmation. You may ask the user to approve individual commands or switch modes via /safe-shell.`
          : mode === "whitelist"
            ? `Only whitelisted bash patterns are allowed. Session has ${approvals} command approval(s). You may ask the user to approve additional commands via /safe-shell.`
            : `⚠️ YOLO MODE: All commands allowed except denylist items. Use with extreme caution. Session has ${approvals} command approval(s).`);

    return {
      systemPrompt: _event.systemPrompt + `\n\n## Safe Shell\n\n${modeHint}`,
    };
  });

  // ---- Event: tool_call — the bash gate (extends to all shell-executing tools) ----
  pi.on("tool_call", async (event, ctx) => {
    // Extract shell command info from any tool call
    const input = event.input as Record<string, unknown>;

    let tool: string;
    let command: string;
    let commands: string[] | undefined;

    if (event.toolName === "bash") {
      const raw = input?.command;
      const cmd = typeof raw === "string" ? raw.trim() : "";
      if (!cmd) return undefined;
      tool = "bash";
      command = cmd;
    } else if (event.toolName === "ctx_execute") {
      const raw = input?.code;
      const cmd = typeof raw === "string" ? raw.trim() : "";
      if (!cmd) return undefined;

      if (input?.language === "shell") {
        tool = "ctx_execute";
        command = cmd;
      } else {
        // Heuristic: check non-shell code for child_process shell-execution patterns
        const matchedPattern = SHELL_EXEC_PATTERNS.find((p) => p.pattern.test(cmd));
        if (!matchedPattern) return undefined; // Pure code analysis — pass through

        // Try to extract the actual shell command from child_process calls
        const extractedCmd = tryExtractShellCommand(cmd);
        tool = "ctx_execute";
        command = extractedCmd ?? `JS operation (${matchedPattern.label})`;
        // Use a tool label that indicates this went through heuristic detection
      }
    } else if (event.toolName === "interactive_shell") {
      // Check command string first
      const raw = input?.command;
      const cmd = typeof raw === "string" ? raw.trim() : "";
      if (cmd) {
        tool = "interactive_shell";
        command = cmd;
      } else {
        // Check spawn-based invocation (pi, claude, codex, cursor)
        const spawn = input?.spawn as Record<string, unknown> | undefined;
        if (spawn?.prompt && typeof spawn.prompt === "string") {
          tool = "interactive_shell";
          command = spawn.prompt.trim();
        } else {
          // Idle interactive session — no specific command, still a shell
          tool = "interactive_shell";
          command = "(interactive session)";
        }
      }
    } else if (event.toolName === "ctx_batch_execute") {
      const cmds = input?.commands;
      if (!Array.isArray(cmds) || cmds.length === 0) return undefined;
      const extracted: string[] = [];
      for (const entry of cmds) {
        const rawCmd = (entry as Record<string, unknown>)?.command;
        if (typeof rawCmd === "string" && rawCmd.trim()) {
          extracted.push(rawCmd.trim());
        }
      }
      if (extracted.length === 0) return undefined;
      tool = "ctx_batch_execute";
      command = extracted.join(" ; ");
      commands = extracted;
    } else if (event.toolName === "write" || event.toolName === "edit") {
      // CODE-BASED BYPASS PREVENTION: Analyze code content for dangerous APIs
      const code = event.toolName === "write" 
        ? (input?.content as string) || ""
        : (input?.edits as Array<{ newString?: string }>)?.map(e => e.newString || "").join("\n") || "";
      
      if (!code) return undefined;
      
      const filePath = (input?.path as string) || "";
      const analysis = analyzeCode(code, filePath);
      
      // Resolve mode for code analysis
      const merged = mergeConfigs(globalConfig, projectConfig);
      const mode = effectiveMode();
      
      // Block critical-level code in all modes except YOLO
      if (analysis.level === "critical" && mode !== "yolo") {
        return {
          block: true,
          reason: formatCodeBlockMessage(analysis, filePath),
        };
      }
      
      // Require confirmation for danger-level in ask mode
      if (analysis.level === "danger" && mode === "ask") {
        const ok = await ctx.ui.confirm(
          "⚠️ Dangerous Code Detected",
          formatCodeBlockMessage(analysis, filePath),
          { confirmText: "Allow", cancelText: "Block" }
        );
        if (!ok) {
          return { block: true, reason: "Blocked by user" };
        }
      }
      
      // Warn for caution-level or if dangerous calls detected
      if (analysis.dangerousCalls.length > 0) {
        const severity = analysis.level === "caution" ? "warn" : "info";
        ctx.ui.notify(
          `⚡ Code analysis: ${analysis.dangerousCalls.length} dangerous API call(s) detected (${analysis.level}: ${analysis.score}/100)`,
          severity
        );
      }
      
      return undefined; // Allow code to be written
    } else {
      return undefined;
    }

    // Resolve effective config & mode
    const merged = mergeConfigs(globalConfig, projectConfig);
    const mode = effectiveMode();

    // If this is a batch tool (ctx_batch_execute), check each command individually
    const cmdsToCheck = commands ?? [command];

    // Check each command through the full gate
    for (const cmd of cmdsToCheck) {
      const result = await checkShellCommand(cmd, merged, mode, tool, ctx, tempApprovals, (cwd) => {
        const fresh = loadProjectConfig(cwd);
        if (fresh) projectConfig = fresh;
      });
      if (result !== undefined) {
        // For batch tools, prefix with the failing command info
        if (commands && result.block) {
          result.reason =
            `pi-safe-shell [${tool}]: batch command blocked by policy.\n` +
            `  Failing command: ${truncate(cmd, 200)}\n` +
            `  ${result.reason ?? "blocked"}`;
        }
        return result;
      }
    }

    return undefined; // All commands passed
  });

  // ---- Register custom safe tools ----

  pi.registerTool({
    name: "run_tests",
    label: "Run Tests",
    description:
      "Run the project test suite. Capped output prevents overwhelming the context. " +
      "Configured via pi-safe-shell config under testCommand / testCommandArgs.",
    promptSnippet: "Run tests with capped output instead of npm test or pytest via bash",
    parameters: Type.Object({}),
    async execute(_id, _params, signal, _onUpdate, _ctx) {
      const merged = mergeConfigs(globalConfig, projectConfig);
      try {
        const { stdout, stderr } = await execP(merged.testCommand, merged.testCommandArgs, {
          cwd: _ctx.cwd,
          timeout: merged.testTimeout,
          signal,
        });
        const output = (stdout + stderr).slice(-4000) || "(no output)";
        return { content: [{ type: "text", text: output }], details: { exitCode: 0 } };
      } catch (err: unknown) {
        const e = err as { stdout?: string; stderr?: string; message?: string; code?: number };
        const output = ((e.stdout ?? "") + (e.stderr ?? e.message ?? "")).slice(-4000);
        return {
          content: [{ type: "text", text: output }],
          details: { exitCode: e.code ?? 1 },
          isError: true,
        };
      }
    },
  });

  pi.registerTool({
    name: "git_status",
    label: "Git Status",
    description: "Show short git status for the project (porcelain + branch).",
    promptSnippet: "Check git status without using bash",
    parameters: Type.Object({}),
    async execute(_id, _params, signal, _onUpdate, _ctx) {
      try {
        const { stdout } = await execP(
          "git",
          ["status", "--porcelain", "-b"],
          { cwd: _ctx.cwd, signal, timeout: 15_000 },
        );
        return {
          content: [{ type: "text", text: stdout || "(clean)" }],
          details: {},
        };
      } catch (err: unknown) {
        const e = err as { stdout?: string; message?: string };
        return {
          content: [{ type: "text", text: e.message ?? "Unknown error" }],
          details: {},
          isError: true,
        };
      }
    },
  });

  pi.registerTool({
    name: "list_files",
    label: "List Files",
    description:
      "List filenames in a directory. Names only — does NOT return contents. " +
      "Defaults to current directory if no path given.",
    promptSnippet: "List filenames in a directory without reading any file contents",
    parameters: Type.Object({
      path: Type.Optional(
        Type.String({
          description: "Directory path. Defaults to current directory (.)",
        }),
      ),
    }),
    async execute(_id, params, _signal, _onUpdate, _ctx) {
      const target = params.path
        ? resolve(_ctx.cwd, params.path)
        : _ctx.cwd;
      // Ensure resolved path is within the project directory
      if (!target.startsWith(_ctx.cwd)) {
        return {
          content: [{ type: "text" as const, text: `Access denied: path "${params.path}" is outside the project directory.` }],
          details: {},
          isError: true,
        };
      }
      try {
        const entries = readdirSync(target, { withFileTypes: true })
          .map((e) => {
            const suffix = e.isDirectory() ? "/" : "";
            return e.name + suffix;
          })
          .sort();
        return {
          content: [
            {
              type: "text" as const,
              text: entries.length
                ? entries.slice(0, 200).join("\n") + (entries.length > 200 ? `\n... (${entries.length - 200} more)` : "")
                : "(empty directory)",
            },
          ],
          details: { count: entries.length, path: target },
        };
      } catch (err: unknown) {
        const e = err as { message?: string };
        return {
          content: [{ type: "text" as const, text: `Cannot list directory: ${e.message ?? "Unknown error"}` }],
          details: {},
          isError: true,
        };
      }
    },
  });

  // ---- Register safe_shell_mode tool (query only) ----
  pi.registerTool({
    name: "safe_shell_mode",
    label: "Safe Shell: Query Mode",
    description:
      "Query the current pi-safe-shell operating mode (block/ask/whitelist) " +
      "and number of session-level command approvals.",
    promptSnippet:
      "Check the current bash security mode. Cannot change mode — use /safe-shell mode for that.",
    promptGuidelines: [
      "Use safe_shell_mode to proactively check your bash security mode before attempting commands.",
      "If blocked, tell the user your current mode and suggest they use /safe-shell to adjust it.",
    ],
    parameters: Type.Object({}),
    async execute(_id, _params, _signal, _onUpdate, _ctx) {
      const mode = effectiveMode();
      return {
        content: [
          {
            type: "text",
            text:
              `Mode: ${MODE_LABELS[mode]}\n` +
              `Approvals: ${tempApprovals.length} session command(s)`,
          },
        ],
        details: { mode, approvalCount: tempApprovals.length },
      };
    },
  });

  // ---- Register safe_shell_approve tool (list/allow/deny with confirm) ----
  function reloadProjectConfig(cwd: string): void {
    const fresh = loadProjectConfig(cwd);
    if (fresh) projectConfig = fresh;
  }
  pi.registerTool({
    name: "safe_shell_approve",
    label: "Safe Shell: Manage Approvals",
    description:
      "List, add, or remove session-level command approvals. " +
      "Allow and deny require user confirmation.",
    promptSnippet: "Manage approved bash commands for this session",
    parameters: Type.Object({
      action: StringEnum(
        ["list", "allow", "deny"] as const,
        { description: "Action: list approvals, allow a command, or deny (remove) a command" },
      ),
      command: Type.Optional(
        Type.String({ description: "The command to allow or deny (required for allow/deny)" }),
      ),
    }),
    async execute(_id, params, _signal, _onUpdate, ctx) {
      if (params.action === "list") {
        const list =
          tempApprovals.length > 0
            ? tempApprovals.map((a) => `  • ${a}`).join("\n")
            : "(none)";
        return {
          content: [
            { type: "text" as const, text: `Session approvals (${tempApprovals.length}):\n${list}` },
          ],
          details: { approvals: [...tempApprovals] },
        };
      }

      if (params.action === "allow") {
        if (!params.command) {
          return {
            content: [{ type: "text" as const, text: "Error: command is required for allow action." }],
            isError: true,
          };
        }
        const choice = await ctx.ui.select(
          `Approve command?\n\n  ${params.command}`,
          ["Allow Once", "Allow Always", "Allow for Project", "Deny"],
        );
        if (!choice || choice === "Deny") {
          return {
            content: [{ type: "text" as const, text: "Approval cancelled by user." }],
            details: {},
          };
        }
        if (choice === "Allow Always") {
          tempApprovals.push(params.command.trim());
          persistState();
        }
        if (choice === "Allow for Project") {
          tempApprovals.push(params.command.trim());
          persistState();
          if (persistAllowToProject(ctx.cwd, params.command.trim())) {
            reloadProjectConfig(ctx.cwd);
          }
        }
        return {
          content: [{ type: "text" as const, text: `Approved: ${params.command}` }],
          details: { approvals: [...tempApprovals] },
        };
      }

      if (params.action === "deny") {
        if (!params.command) {
          return {
            content: [{ type: "text" as const, text: "Error: command is required for deny action." }],
            isError: true,
          };
        }
        const index = tempApprovals.indexOf(params.command.trim());
        if (index === -1) {
          return {
            content: [
              { type: "text" as const, text: `Not in session approvals: ${params.command}` },
            ],
            details: { approvals: [...tempApprovals] },
          };
        }
        const ok = await ctx.ui.confirm(
          "Remove approval?",
          `Remove this command from session approvals?\n\n  ${params.command}`,
        );
        if (!ok) {
          return {
            content: [{ type: "text" as const, text: "Removal cancelled by user." }],
            details: { approvals: [...tempApprovals] },
          };
        }
        tempApprovals.splice(index, 1);
        persistState();
        return {
          content: [{ type: "text" as const, text: `Removed approval: ${params.command}` }],
          details: { approvals: [...tempApprovals] },
        };
      }

      return {
        content: [{ type: "text" as const, text: `Unknown action: ${params.action}` }],
        isError: true,
      };
    },
  });

  // ---- Register /safe-shell command ----
  pi.registerCommand("safe-shell", {
    description: "Show or change pi-safe-shell mode and approvals",
    handler: async (args: string, ctx: ExtensionContext) => {
      const merged = mergeConfigs(globalConfig, projectConfig);
      const mode = effectiveMode();
      const parts = args.trim().split(/\s+/);

      if (parts.length === 0 || parts[0] === "") {
        // Show status
        const lines: string[] = [
          "",
          "╔══════════════════════════════════════════╗",
          `║  pi-safe-shell                            ║`,
          `║  Mode:      ${MODE_LABELS[mode].padEnd(32)}║`,
          `║  Approvals: ${tempApprovals.length} session command(s)           ║`,
          `║  Whitelist: ${merged.whitelist.length} pattern(s)                ║`,
          `║  Denylist:  ${merged.denylist.length} pattern(s)                 ║`,
          "╚══════════════════════════════════════════╝",
          "",
          "Commands:",
          "  /safe-shell                       Show this status",
          "  /safe-shell mode block|ask|whitelist|yolo   Switch operating mode",
          "  /safe-shell allow <command> [--project]   Approve a command (--project persists to project)",
          "  /safe-shell deny <command> [--project]    Remove approval (--project removes from project)",
          "",
        ];

        if (tempApprovals.length > 0) {
          lines.push("Session approvals:");
          for (const a of tempApprovals) {
            lines.push(`  • ${a}`);
          }
          lines.push("");
        }

        ctx.ui.notify(lines.join("\n"), "info");
        return;
      }

      const subcommand = parts[0].toLowerCase();
      const value = parts.slice(1).join(" ");

      switch (subcommand) {
        case "mode": {
          const target = value;
          if (!["block", "ask", "whitelist", "yolo"].includes(target)) {
            ctx.ui.notify(
              `Invalid mode "${target}". Use: block, ask, whitelist, or yolo.`,
              "error",
            );
            return;
          }

          sessionMode = target as Mode;
          persistState();
          if (ctx.hasUI) {
            ctx.ui.notify(
              `pi-safe-shell: switched to "${target}" mode for this session.`,
              "info",
            );
          }
          return;
        }

        case "allow": {
          if (!value) {
            ctx.ui.notify("Usage: /safe-shell allow <command> [--project]", "error");
            return;
          }

          // Parse --project flag
          let targetCommand = value.trim();
          let isProject = false;
          if (targetCommand.endsWith(" --project")) {
            isProject = true;
            targetCommand = targetCommand.slice(0, -10).trimEnd();
          }

          if (isProject) {
            // Persist to project config
            const projectConfigPath = join(ctx.cwd, ".pi", "pi-safe-shell.json");
            let projectCfg: any = {};
            if (existsSync(projectConfigPath)) {
              try {
                projectCfg = JSON.parse(readFileSync(projectConfigPath, "utf-8"));
              } catch {
                ctx.ui.notify("Corrupt project config. Creating new one.", "warning");
                projectCfg = {};
              }
            }
            if (!Array.isArray(projectCfg.whitelist)) {
              projectCfg.whitelist = [];
            }
            if (projectCfg.whitelist.includes(targetCommand)) {
              ctx.ui.notify(`Already in project whitelist: ${targetCommand}`, "warning");
              return;
            }
            projectCfg.whitelist.push(targetCommand);
            const dir = join(ctx.cwd, ".pi");
            if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
            writeFileSync(projectConfigPath, JSON.stringify(projectCfg, null, 2), "utf-8");
            // Reload project config
            projectConfig = loadProjectConfig(ctx.cwd);
            ctx.ui.notify(`Added to project whitelist: ${targetCommand}`, "info");
            return;
          }

          // Check if already approved
          if (tempApprovals.includes(targetCommand)) {
            ctx.ui.notify(`Already approved: ${value}`, "warning");
            return;
          }

          tempApprovals.push(targetCommand);
          persistState();
          ctx.ui.notify(`Approved: ${targetCommand}`, "info");
          return;
        }

        case "deny": {
          if (!value) {
            ctx.ui.notify("Usage: /safe-shell deny <command> [--project]", "error");
            return;
          }

          // Parse --project flag
          let targetCommand = value.trim();
          let isProject = false;
          if (targetCommand.endsWith(" --project")) {
            isProject = true;
            targetCommand = targetCommand.slice(0, -10).trimEnd();
          }

          if (isProject) {
            // Remove from project config
            const projectConfigPath = join(ctx.cwd, ".pi", "pi-safe-shell.json");
            if (!existsSync(projectConfigPath)) {
              ctx.ui.notify("No project config found.", "warning");
              return;
            }
            let projectCfg: any = {};
            try {
              projectCfg = JSON.parse(readFileSync(projectConfigPath, "utf-8"));
            } catch {
              ctx.ui.notify("Corrupt project config.", "error");
              return;
            }
            if (!Array.isArray(projectCfg.whitelist)) {
              ctx.ui.notify(`Not in project whitelist: ${targetCommand}`, "warning");
              return;
            }
            const idx = projectCfg.whitelist.indexOf(targetCommand);
            if (idx === -1) {
              ctx.ui.notify(`Not in project whitelist: ${targetCommand}`, "warning");
              return;
            }
            projectCfg.whitelist.splice(idx, 1);
            writeFileSync(projectConfigPath, JSON.stringify(projectCfg, null, 2), "utf-8");
            projectConfig = loadProjectConfig(ctx.cwd);
            ctx.ui.notify(`Removed from project whitelist: ${targetCommand}`, "info");
            return;
          }

          const index = tempApprovals.indexOf(targetCommand);
          if (index === -1) {
            ctx.ui.notify(`Not in session approvals: ${targetCommand}`, "warning");
            return;
          }

          tempApprovals.splice(index, 1);
          persistState();
          ctx.ui.notify(`Removed approval: ${targetCommand}`, "info");
          return;
        }

        default:
          ctx.ui.notify(
            `Unknown subcommand: ${subcommand}. Use mode, allow, or deny.`,
            "error",
          );
      }
    },
  });

  // ---- Render custom state messages ----
  pi.registerMessageRenderer(SESSION_STATE_TYPE, (_message, _options, theme) => {
    return new Text(
      theme.fg("dim", `[pi-safe-shell] mode=${effectiveMode()}, ${tempApprovals.length} approvals`),
      0,
      0,
    );
  });
}
