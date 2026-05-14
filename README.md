# pi-safe-shell 🛡️

**Protect your production assets from dangerous bash commands.**

A [Pi](https://github.com/earendil-works/pi-coding-agent) extension that gates bash and all shell-executing tools with four security modes, inspired by the [bash-damage-from-within](https://github.com/disler/bash-damage-from-within) project.

> Default: **🔒 Block** mode — the agent cannot run any shell commands unless you explicitly allow them.
> 
> **New:** **🚀 YOLO** mode — allow everything except denylist items. Use with extreme caution.
> 
> **New in v0.3.0:** **AST-based semantic analysis** with auto-blocking for critical risks.

**Repository:** [github.com/aslamplr/pi-safe-shell](https://github.com/aslamplr/pi-safe-shell)

**Version:** 0.3.0

---

## Installation

### Option 1: Run from source

```bash
pi -e ./path/to/pi-safe-shell/index.ts
```

### Option 2: Manual install to auto-discovered location

```bash
# Clone the repository
git clone https://github.com/aslamplr/pi-safe-shell.git ~/.pi/agent/extensions/pi-safe-shell

# Or copy manually
cp -r pi-safe-shell ~/.pi/agent/extensions/
```

After installation, the extension loads automatically in all Pi sessions.

### Option 3: Install via npm

```bash
pi install npm:@aslamplr/pi-safe-shell
```

> **Note:** Replace `@aslamplr/pi-safe-shell` with the latest version tag.

---

## Four Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **🔒 Block** (default) | All shell calls blocked. Agent uses Read/Write/Edit + safe registered tools. | Maximum safety. You're in control. |
| **❓ Ask** | Each shell call shows a selection prompt with 4 options. | Selective override without mode-switching. |
| **🔓 Whitelist** | Only commands matching curated safe patterns pass through. Compound shell operators rejected. | Standard dev workflow. |
| **🚀 YOLO** | All commands allowed EXCEPT denylist items. No prompts, no whitelist check. | Maximum freedom with minimal safety net. Use with extreme caution. |

### AST-Based Semantic Analysis (Phase 3)

pi-safe-shell uses **tree-sitter-bash** to parse and analyze shell commands semantically. This detects dangerous patterns that simple regex matching would miss:

**Detection Capabilities:**
- **Intent classification** - 12 intent types (Delete, Network, Execute, CodeExecution, etc.)
- **Path scope analysis** - System (`/etc`), home (`~`), project (`./`), temp (`/tmp`)
- **Dangerous flags** - `-rf`, `-R`, `-f`, `--force`, `--no-preserve-root` (context-aware)
- **Pipeline patterns** - `curl|bash`, `wget|bash`, data exfiltration (`cat .env|curl`)
- **Command chaining** - `&&`, `||`, `;` operators analyzed for each command in chain
- **Interpreter detection** - `python -c`, `node -e`, `sh -c`, `bash -c`, `eval`
- **Inline code parsing** - Recursively analyzes code inside `-c/-e` flags

**Risk Levels:**
- **🟢 Safe (≤20)** - Info queries, reads, benign operations
- **🟡 Caution (21-50)** - Writes, git changes, inline code execution
- **🟠 Danger (51-80)** - Deletes, privilege escalation, network operations
- **🔴 Critical (81-100)** - Destructive ops (`rm -rf /`), RCE (`curl|bash`), data exfil

**Blocking Policy:**
- **Critical (≥81)** - Auto-blocked in all modes except YOLO
- **Danger (51-80)** - Requires confirmation in `ask` mode
- **Caution/Safe** - Allowed with logging

See [INLINE_CODE_PARSING.md](INLINE_CODE_PARSING.md) and [COMMAND_CHAINING_ANALYSIS.md](COMMAND_CHAINING_ANALYSIS.md) for implementation details.

### Switch modes mid-session

```
/safe-shell mode ask
/safe-shell mode whitelist
/safe-shell mode block
/safe-shell mode yolo
```

---

## Gate Coverage

The shell gate intercepts **all** tools that can execute shell commands, not just `bash`:

| Tool | How it's gated |
|------|---------------|
| **`bash`** | The `command` parameter is checked directly |
| **`ctx_execute`** with `language="shell"` | The `code` parameter is checked as a shell command |
| **`ctx_execute`** JS/Python | Heuristically scanned for `child_process` / `subprocess` / `os.system` patterns. Extracted command strings are gated; pure code analysis passes through |
| **`interactive_shell`** | The `command` or `spawn.prompt` parameter is checked |
| **`ctx_batch_execute`** | Each command in the batch is checked individually |

### Heuristic detection for JS/Python ctx_execute

For `ctx_execute` calls with non-shell languages (JS, Python), the gate scans the code for shell execution patterns:

**Node.js patterns:** `execSync(`, `execFileSync(`, `exec(`, `spawn(`, `spawnSync(`, `child_process`, `shell: true`, `fork(`

**Python patterns:** `os.system(`, `os.popen(`, `subprocess.run(`, `subprocess.call(`, `subprocess.check_output(`, `subprocess.Popen(`, `subprocess.check_call(`, `shell=True`

When a command string can be extracted (e.g., `execSync('rm -rf target/')`), that command is gated. When it can't be extracted, a generic descriptor like `JS operation (execSync)` is used. Pure code analysis (no shell patterns) passes through ungated.

---

## Approval Dialog (Ask Mode)

When a shell command is attempted in **Ask** mode, you see a selection prompt:

```
🐚 pi-safe-shell: allow this command?

  Tool: bash
  Command: rm -rf target/

→ Allow Once        Let this command run once
  Allow Always      Always allow in this session
  Allow for Project  Persist to project whitelist (.pi/pi-safe-shell.json)
  Deny              Block this command
```

| Option | What it does | Persists across |
|--------|-------------|-----------------|
| **Allow Once** | Runs the command now, not added to approvals | This turn only |
| **Allow Always** | Adds to session approvals (+ persists via `pi.appendEntry`) | Session restart (`/resume`) |
| **Allow for Project** | Adds to session approvals AND writes to project whitelist | Session restart AND project config |
| **Deny** | Blocks the command | — |

The same 4 options are also available when the agent calls `safe_shell_approve` tool to request approval.

---

## Agent Tools

The extension registers two tools the agent can use proactively:

### `safe_shell_mode`

Query-only tool for the agent to check the current security mode and approval count. No user interaction required.

### `safe_shell_approve`

Tool for the agent to list, add, or remove session approvals. Requires `action` and `command` parameters. Shows a user confirmation dialog.

```
safe_shell_approve({ action: "allow", command: "rm -rf target/" })
  → User sees: Allow Once / Allow Always / Allow for Project / Deny
  → If approved: command is added to session approvals and/or project whitelist
```

**Important:** Approvals are checked before the mode switch, so they work in all three modes — even Block mode.

---

## Commands

| Command | Action |
|---------|--------|
| `/safe-shell` | Show current mode, approval count, and config summary |
| `/safe-shell mode block\|ask\|whitelist` | Switch operating mode for this session |
| `/safe-shell allow <command>` | Approve a command for this session |
| `/safe-shell allow <command> --project` | Persist approval to project whitelist (`.pi/pi-safe-shell.json`) |
| `/safe-shell deny <command>` | Remove a session approval |
| `/safe-shell deny <command> --project` | Remove from project whitelist |

### Example: allow a deployment

```
/safe-shell allow npm run deploy
```

Now `npm run deploy` can execute through bash. Other commands remain blocked.

---

## Safe Registered Tools

Three custom tools are registered as safe alternatives to common bash tasks:

| Tool | What it does | Why it's safe |
|------|-------------|---------------|
| **`run_tests`** | Runs the configured test command (`uv run pytest -q` by default) | Output capped at 4KB |
| **`git_status`** | Shows `git status --porcelain -b` | Read-only, no mutation |
| **`list_files`** | Lists filenames in a directory | Names only — no file contents revealed |

The agent is told about these tools so it can use them instead of reaching for bash.

### Configure test tool

In project config (`.pi/pi-safe-shell.json`):

```json
{
  "testCommand": "npm",
  "testCommandArgs": ["test"],
  "testTimeout": 60000
}
```

---

## Configuration Files

Three layers, highest priority first:

### 1. Session state (auto-managed)

Commands you approve via `/safe-shell allow` or via the ask-mode dialog persist in the session file. They survive `/resume` but not `/new`.

### 2. Project config (`.pi/pi-safe-shell.json`)

Per-project overrides. Place at your project root:

```json
{
  "mode": "whitelist",
  "whitelist": [
    "^pnpm run build$",
    "^pnpm test$",
    "^npx [\\w@./\\-]+(\\s+[\\w./\\-]+)*$",
    "^git push origin main$"
  ],
  "denylist": ["rm -rf"],
  "rejectCompoundOperators": true,
  "testCommand": "pnpm",
  "testCommandArgs": ["test"]
}
```

### 3. Global config (`~/.pi/agent/extensions/pi-safe-shell/config.json`)

Default for all projects. Auto-created on first run:

```json
{
  "defaultMode": "block",
  "whitelist": [
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
    "^date$"
  ],
  "denylist": [
    "rm -rf /",
    "rm -rf ~",
    "rm -rf .",
    "sudo",
    "> /dev",
    "mkfs",
    "dd if=",
    ":(){ :|:& };:",
    "chmod 777",
    "chown -R"
  ],
  "rejectCompoundOperators": true,
  "testCommand": "uv",
  "testCommandArgs": ["run", "pytest", "-q"],
  "testTimeout": 120000
}
```

### Config precedence

```
Session temp approvals (highest)
        ↓ overrides
Project config (.pi/pi-safe-shell.json)
        ↓ overrides
Global config (~/.pi/agent/extensions/pi-safe-shell/config.json)
        ↓ fallback
Hardcoded defaults
```

---

## Architecture

```
Any shell tool call (bash, ctx_execute, interactive_shell, ctx_batch_execute)
    │
    ▼
1. Denylist check (token-based exact match) ──── match? → BLOCK ⛔
    │
    ▼ (no match)
2. Session temp approvals check ──── match? → ALLOW ✅
    │
    ▼ (no match)
3. Mode switch
    │
    ├─ 🔒 block    → BLOCK ⛔ (with guidance to use safe tools)
    │
    ├─ ❓ ask      → Show user dialog
    │                ├─ Allow Once         → ALLOW ✅
    │                ├─ Allow Always       → ALLOW ✅ + session persist
    │                ├─ Allow for Project  → ALLOW ✅ + session + project whitelist
    │                └─ Deny               → BLOCK ⛔
    │
    └─ 🔓 whitelist → Check compound operators → reject? → BLOCK ⛔
                       Check whitelist regex patterns
                         ├─ match? → ALLOW ✅
                         └─ no     → BLOCK ⛔ (with hint to /safe-shell allow)
```

### Heuristic gate path (JS/Python ctx_execute)

```
ctx_execute (language=javascript or python)
    │
    ▼
Scan code for shell-execution patterns
    │
    ├─ No patterns found → PASS THROUGH (pure code analysis) ✅
    │
    └─ Pattern found → Extract command string if possible
                        │
                        ├─ Extracted → gate the extracted command
                        └─ Not extractable → gate as generic descriptor
                           (e.g., "JS operation (execSync)")
```

---

## Development

```bash
# Clone the repository
git clone https://github.com/aslamplr/pi-safe-shell.git
cd pi-safe-shell

# Install dependencies
npm install

# Run with the extension
pi -e ./index.ts

# Run tests
npm test
```

### File structure

```
pi-safe-shell/
├── index.ts         # Main extension (~1100 lines)
├── index.test.ts    # Test suite (84+ tests)
├── package.json     # Package metadata (pi install compatible)
├── tsconfig.json    # TypeScript config
└── README.md        # This file
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Releasing (Publishing to npm)

Publishing to npm is a **manual, explicit decision** to ensure stability and prevent accidental releases.

### Prerequisites

1. **GitHub secret**: Set `NPM_TOKEN` in repository settings
   - Go to: `Settings` → `Secrets and variables` → `Actions`
   - Click `New repository secret`
   - Name: `NPM_TOKEN`
   - Value: Your npm access token (get from https://www.npmjs.com/settings/YOUR_USERNAME/tokens)
   - Token must have `Publish` permission

2. **Update version in package.json**:
   ```bash
   # Edit package.json, update version field (e.g., "0.1.0" -> "0.2.0")
   # Follow semver: MAJOR.MINOR.PATCH
   ```

3. **Commit and push**:
   ```bash
   git add package.json
   git commit -m "chore: bump version to 0.2.0"
   git push origin main
   ```

### Publish Workflow

1. **Navigate to GitHub Actions**:
   - Go to: `https://github.com/aslamplr/pi-safe-shell/actions`
   - Click on workflow: `CD (Publish to npm)`

2. **Trigger manual run**:
   - Click `Run workflow` button
   - Select branch: `main`
   - Enter version: `0.2.0` (must match package.json exactly)
   - Click `Run workflow`

3. **Workflow execution**:
   - ✅ CI checks run first (tests + type-checking)
   - ✅ Version validation (package.json must match input)
   - ✅ npm publish with provenance

4. **Verify publish**:
   - Check workflow run output for success
   - Verify on npm: https://www.npmjs.com/package/@aslamplr/pi-safe-shell
   - Install test: `pi install npm:@aslamplr/pi-safe-shell@0.2.0`

### Troubleshooting

**Workflow fails with version mismatch:**
- Ensure package.json version matches the version input exactly
- Example: package.json has `"0.2.0"`, workflow input must be `0.2.0`

**Workflow fails with auth error:**
- Verify `NPM_TOKEN` secret is set correctly
- Check token has `Publish` permission
- Token may have expired - regenerate if needed

**Package already exists:**
- Version must be unique - bump version in package.json
- npm does not allow overwriting published versions

---

## Changelog

### v0.3.0 (2026-05-14)

**Phase 3: AST-Based Blocking** 🎉

- ✅ **Auto-block CRITICAL risks** (score ≥81) in all modes except YOLO
  - Destructive ops: `rm -rf /`, `dd if=/dev/zero`, `mkfs`, `fdisk`
  - RCE patterns: `curl|bash`, `wget|sh`
  - Interpreter attacks: `sh -c "..."`, `python -c "..."`, `node -e "..."`
  - Command chaining: `&&`, `||`, `;` with destructive ops
  - Data exfiltration: `cat|curl`, `tar|wget`
- ✅ **Require confirmation for DANGER risks** (51-80) in `ask` mode
- ✅ **Inline code parsing** - Extract and analyze code from `-c/-e` flags
- ✅ **Command chaining detection** - Analyze each command in chains
- ✅ **Interpreter bypass detection** - Detect `python -c`, `node -e`, `sh -c`, `bash -c`
- ✅ **12 intent types** - Delete, Network, Execute, CodeExecution, etc.
- ✅ **Path scope analysis** - System, home, project, temp paths
- ✅ **Risk factor tracking** - 25+ risk factors for enhanced diagnostics
- 📚 **Documentation:**
  - `INLINE_CODE_PARSING.md` - Inline code extraction implementation
  - `COMMAND_CHAINING_ANALYSIS.md` - Chaining detection implementation
  - `PHASE_3_BLOCKING.md` - Phase 3 blocking policy and examples
  - `AST_ANALYZER_TEST_RESULTS.md` - Comprehensive test report

**Test Results:** 88.1% pass rate (37/42 tests)

**Dependencies:**
- Added: `tree-sitter-bash` (^0.25.1)
- Added: `web-tree-sitter` (^0.26.8)

### v0.2.0 (2026-05-13)

**YOLO Mode + CI/CD**

- ✅ Added **YOLO mode** - Allow everything except denylist items
- ✅ Created GitHub Actions workflows (ci.yml, cd.yml)
- ✅ Updated README with installation instructions
- ✅ Added Limitations & Warnings section
- ✅ Added No Warranty section
- ✅ Scoped npm package: `@aslamplr/pi-safe-shell`

### v0.1.0 (2026-05-12)

**Initial Release**

- ✅ Four security modes: Block, Ask, Whitelist, YOLO
- ✅ Pattern-based denylist/whitelist matching
- ✅ Session-level temp approvals
- ✅ Heuristic detection for JS/Python `ctx_execute`

---

## ⚠️ Limitations & Warnings

**This extension is not bulletproof.** While it provides strong protection against common shell command execution paths, determined agents or sophisticated code can potentially bypass these safeguards:

### Known Limitations

1. **Pure code execution**: An agent could write pure JavaScript/Python code that executes shell commands using techniques not covered by the heuristic patterns (e.g., dynamic imports, eval-based execution, native bindings, FFI calls).

2. **Unmonitored tools**: The extension gates known shell-executing tools (`bash`, `ctx_execute`, `interactive_shell`, `ctx_batch_execute`). New tools, MCP servers, or custom extensions that execute shell commands are not automatically gated.

3. **Pattern evasion**: The heuristic detection for JS/Python `ctx_execute` calls uses pattern matching. Obfuscated or dynamically constructed shell commands may evade detection.

4. **External processes**: Agents could potentially spawn processes through other means (e.g., Node.js worker threads, Python multiprocessing, platform-specific APIs) that bypass the gate.

5. **Mid-session changes**: If the extension is loaded mid-session or reloaded, there may be transient states where protections are not fully active.

**Use this extension as one layer of defense, not as your only security measure.** Always review agent-generated code before execution, especially when granting broad permissions.

---

## ⚖️ No Warranty

**THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.**

In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

**USE THIS EXTENSION AT YOUR OWN RISK.** The authors make no representations or warranties that this extension will prevent all shell command execution, protect against all malicious code, or be error-free. You are solely responsible for:

- Reviewing and understanding the code this extension protects
- Configuring appropriate security policies for your use case
- Monitoring agent behavior and system activity
- Maintaining backups of important data and production assets

By using this extension, you acknowledge that you have read and understood these limitations and agree to use the software at your own discretion and risk.

---

## Credits

Inspired by [bash-damage-from-within](https://github.com/disler/bash-damage-from-within) by [IndyDevDan](https://www.youtube.com/@indydevdan) — a brilliant 5-level ladder for securing agentic bash access.

---

## License

MIT
