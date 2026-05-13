# pi-safe-shell 🛡️

**Protect your production assets from dangerous bash commands.**

A [Pi](https://github.com/earendil-works/pi-coding-agent) extension that gates bash and all shell-executing tools with three security modes, inspired by the [bash-damage-from-within](https://github.com/disler/bash-damage-from-within) project.

> Default: **🔒 Block** mode — the agent cannot run any shell commands unless you explicitly allow them.

---

## Quick Start

```bash
# Install via pi
pi install npm:pi-safe-shell

# Or run from source
pi -e /path/to/pi-safe-shell/index.ts

# Or copy to auto-discovered location
cp -r pi-safe-shell ~/.pi/agent/extensions/
```

---

## Three Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **🔒 Block** (default) | All shell calls blocked. Agent uses Read/Write/Edit + safe registered tools. | Maximum safety. You're in control. |
| **❓ Ask** | Each shell call shows a selection prompt with 4 options. | Selective override without mode-switching. |
| **🔓 Whitelist** | Only commands matching curated safe patterns pass through. Compound shell operators rejected. | Standard dev workflow. |

### Switch modes mid-session

```
/safe-shell mode ask
/safe-shell mode whitelist
/safe-shell mode block
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

---

## Credits

Inspired by [bash-damage-from-within](https://github.com/disler/bash-damage-from-within) by [IndyDevDan](https://www.youtube.com/@indydevdan) — a brilliant 5-level ladder for securing agentic bash access.

---

## License

MIT
