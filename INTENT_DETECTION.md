# Intent Detection System for pi-safe-shell

## Overview

The intent detection system enhances pi-safe-shell by automatically learning from user approvals and auto-approving repetitive safe commands. This reduces friction while maintaining security.

## Architecture

### Multi-Layer Analysis

1. **Command Safety Classification** - Categorizes commands as:
   - **Safe**: Read-only operations (grep, cat, ls, git status)
   - **Contextual**: Depends on arguments (git checkout, npm install)
   - **Dangerous**: Inherently destructive (rm, chmod, sudo)

2. **Path Classification** - Evaluates path safety:
   - **PROJECT_SAFE**: Within project root
   - **USER_SPACE**: Home directory (~/Documents, ~/Code)
   - **SYSTEM**: System directories (/etc, /usr, /bin)
   - **ROOT_DANGEROUS**: Root directory (/)

3. **Template Abstraction** - Generalizes commands:
   - `grep "Overview" README.md` → `grep [STRING] [PATH]`
   - `grep "API Design" README.md` → `grep [STRING] [PATH]` ✓ Match!

4. **Session Learning** - Tracks approval patterns:
   - Counts approvals per template
   - Auto-approves when threshold is met
   - Resets each session (opt-in persistence available)

## Configuration Modes

| Mode | Safe Commands | Contextual Commands | Dangerous Commands |
|------|--------------|---------------------|-------------------|
| `sandbox` | 1 approval | 1 approval | Never |
| `development` | 1 approval | 2 approvals | Never |
| `production` | 2 approvals | 3 approvals | Never |
| `migration` | 2 approvals | Always ask | Always ask |

**Default**: `production` (most conservative)

## Path-Aware Thresholds

User space paths require **+1 approval** over the base threshold:

```
development mode:
- cat README.md (PROJECT_SAFE) → 1 approval needed
- cat ~/Documents/notes.txt (USER_SPACE) → 2 approvals needed
```

## Usage Examples

### Example 1: Documentation Review Session

```bash
# First command - requires approval
grep "API" README.md  # ❓ Ask

# User approves

# Subsequent grep commands auto-approve
grep "Overview" README.md  # ✓ Auto-approved
grep "Usage" docs/setup.md  # ✓ Auto-approved
grep "Configuration" docs/config.md  # ✓ Auto-approved
```

### Example 2: Git Workflow

```bash
# Git read operations (safe)
git status  # ❓ Ask (first time)
git status  # ✓ Auto-approved (template matched)
git log --oneline  # ❓ Ask (different template)
git diff HEAD  # ❓ Ask (different template)

# Git mutations (contextual, need more approvals)
git checkout feature-branch  # ❓ Ask
git checkout main  # ❓ Ask (need 2-3 approvals in production mode)
```

### Example 3: Path-Aware Safety

```bash
# Project path - auto-approve after threshold
cat src/index.ts  # ❓ Ask
cat src/index.ts  # ✓ Auto-approved (production mode: 2 approvals)

# System path - never auto-approve
cat /etc/passwd  # ❓ Ask (always)
cat /etc/passwd  # ❓ Ask (always - system path)
```

## API Reference

### Command Safety Classification

```typescript
import { classifyCommandSafety, CommandSafety } from './intent-detector';

classifyCommandSafety('grep "pattern" file.txt');  // CommandSafety.Safe
classifyCommandSafety('git checkout main');        // CommandSafety.Contextual
classifyCommandSafety('rm -rf node_modules');      // CommandSafety.Dangerous
```

### Path Classification

```typescript
import { classifyPath, PathSafety } from './intent-detector';

const projectRoot = '/path/to/project';

classifyPath('./src/index.ts', projectRoot);           // PROJECT_SAFE
classifyPath('~/Documents/file.txt', projectRoot);     // USER_SPACE
classifyPath('/etc/passwd', projectRoot);              // SYSTEM
classifyPath('/', projectRoot);                        // ROOT_DANGEROUS
```

### Template Extraction

```typescript
import { extractTemplate, templatesMatch } from './intent-detector';

const t1 = extractTemplate('grep "Overview" README.md');
// { baseCommand: 'grep', slots: [STRING, PATH], rawTemplate: 'grep [STRING] [PATH]' }

const t2 = extractTemplate('grep "API Design" README.md');
// { baseCommand: 'grep', slots: [STRING, PATH], rawTemplate: 'grep [STRING] [PATH]' }

templatesMatch(t1, t2);  // true
```

### Intent Detector Class

```typescript
import { createIntentDetector } from './intent-detector';

const detector = createIntentDetector({
  projectRoot: '/path/to/project',
  mode: 'development',  // sandbox | development | production | migration
  pathOverrides: {
    './scripts/deploy.sh': PathSafety.System,  // Custom path classification
  },
});

// Analyze a command
const result = detector.analyze('grep "pattern" README.md');
// {
//   shouldAutoApprove: false,
//   reason: 'Command safety: safe | Path: PROJECT_SAFE | REQUIRES APPROVAL (threshold not met (0/2))',
//   safety: CommandSafety.Safe,
//   pathSafety: PathSafety.PROJECT_SAFE,
//   template: { baseCommand: 'grep', slots: [...], rawTemplate: '...' },
//   approvalCount: 0
// }

// Record an approval
detector.recordApproval('grep "pattern" README.md');

// Get statistics
const stats = detector.getStats();
// { totalTemplates: 1, totalApprovals: 1, topTemplates: [...] }
```

## Configuration

### Global Config (~/.pi/agent/extensions/pi-safe-shell/config.json)

```json
{
  "intentDetection": {
    "mode": "production",
    "persistApprovals": false,
    "scope": "per-project",
    "pathOverrides": {
      "./scripts/deploy.sh": "SYSTEM",
      "~/safe-space": "PROJECT_SAFE"
    }
  }
}
```

### Project Config (.pi/pi-safe-shell.json)

```json
{
  "intentDetection": {
    "mode": "development",
    "pathOverrides": {
      "./local-scripts/": "PROJECT_SAFE"
    }
  }
}
```

## Implementation Status

✅ Core functionality implemented:
- Command safety taxonomy
- Path classification with overrides
- Template abstraction with proper tokenization
- Session-based learning
- Mode-based thresholds
- Path-aware threshold adjustments
- Comprehensive test suite (56 tests)

🔜 Future enhancements:
- Persistent approval storage (opt-in)
- Context-aware suggestions (based on conversation topic)
- Workflow pattern detection
- Project-specific profile auto-detection

## Testing

Run tests with:

```bash
npm test -- intent-detector.test.ts
```

Test coverage includes:
- Command safety classification (safe/contextual/dangerous)
- Path classification (project/user/system/root)
- Template extraction and matching
- Mode-based thresholds
- Path-aware auto-approve logic
- Real-world scenario simulations

## Design Principles

1. **Graceful Degradation**: If any layer fails, fall back to "ask"
2. **Transparency**: Always explain WHY a decision was made
3. **User Sovereignty**: User can always override, system learns from overrides
4. **Progressive Trust**: Start conservative, earn auto-approve through consistency
5. **Context Awareness**: Path and command context inform decisions
