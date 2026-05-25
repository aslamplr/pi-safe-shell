# Intent Detector Integration Guide for index.ts

This document shows how to integrate the intent detector into the main pi-safe-shell extension.

## Step 1: Add Import (line ~46)

```typescript
import { initParser, analyzeCommand, scoreCommand, isParserInitialized } from "./src/ast-analyzer";
import { analyzeCode, formatCodeAnalysis, CodeAnalysis } from "./src/code-analyzer";
import { createIntentDetector, type IntentDetector } from "./src/intent-detector";  // ADD THIS
```

## Step 2: Update GlobalConfig Interface (line ~54)

Add these fields to the `GlobalConfig` interface:

```typescript
interface GlobalConfig {
  // ... existing fields ...
  
  // Intent detection
  intentDetectionEnabled: boolean;  // Enable intent-based auto-approve
  intentDetectionMode: 'sandbox' | 'development' | 'production' | 'migration';
  
  // ... rest of fields ...
}
```

## Step 3: Update DEFAULT_CONFIG (line ~108)

Add these fields to `DEFAULT_CONFIG`:

```typescript
const DEFAULT_CONFIG: GlobalConfig = {
  // ... existing fields ...
  
  // Intent detection (enabled by default)
  intentDetectionEnabled: true,
  intentDetectionMode: 'production',  // Most conservative default
  
  // ... rest of fields ...
};
```

## Step 4: Add IntentDetector to Session State (line ~1200)

In the extension entry function, add detector state:

```typescript
export default function (pi: ExtensionAPI) {
  // ---- State (in-memory, reconstructed on session events) ----
  let sessionMode: Mode | undefined;
  let tempApprovals: string[] = [];
  let intentDetector: IntentDetector | null = null;  // ADD THIS
```

## Step 5: Initialize Detector on session_start (line ~1250)

In the `session_start` event handler:

```typescript
pi.on("session_start", async (_event, ctx) => {
  // ... existing config loading ...
  
  // Initialize intent detector
  if (globalConfig.intentDetectionEnabled) {
    intentDetector = createIntentDetector({
      projectRoot: ctx.cwd,
      mode: globalConfig.intentDetectionMode,
      pathOverrides: {},  // Can load from config if needed
    });
  }
  
  // ... rest of initialization ...
});
```

## Step 6: Check Intent in checkShellCommand (line ~700)

In the `checkShellCommand` function, after denylist check:

```typescript
async function checkShellCommand(
  command: string,
  merged: GlobalConfig,
  mode: Mode,
  toolName: string,
  ctx: ExtensionContext,
  tempApprovals: string[],
  intentDetector: IntentDetector | null,  // ADD THIS PARAM
  reloadProjectConfig?: (cwd: string) => void,
): Promise<{ block: boolean; reason?: string } | undefined> {
  // --- 1. Denylist check (always applies) ---
  // ... existing code ...

  // --- 2. Intent detection check (NEW) ---
  if (intentDetector && merged.intentDetectionEnabled) {
    const intentResult = intentDetector.analyze(command);
    
    if (intentResult.shouldAutoApprove) {
      // Auto-approve based on intent analysis
      console.log(`[pi-safe-shell intent] Auto-approved: ${command}`);
      console.log(`  Reason: ${intentResult.reason}`);
      return undefined;  // Allow
    }
    
    // Log when intent detection requires approval
    if (intentResult.safety === 'dangerous' || intentResult.pathSafety === 'SYSTEM') {
      console.log(`[pi-safe-shell intent] Requires approval: ${command}`);
      console.log(`  Reason: ${intentResult.reason}`);
    }
  }

  // --- 3. Session temp approvals check ---
  // ... rest of existing code ...
}
```

## Step 7: Record Approval When User Approves (line ~750)

In the `ask` mode case where user approves:

```typescript
case "ask": {
  // ... existing UI prompt code ...
  
  if (choice === "Allow Once") {
    tempApprovals.push(command);
    persistState();
    // Record approval for intent learning
    intentDetector?.recordApproval(command);  // ADD THIS
  }
  
  if (choice === "Allow Always") {
    tempApprovals.push(command);
    persistState();
    intentDetector?.recordApproval(command);  // ADD THIS
    trackLearningCommand(command, mergedConfig, tempApprovals, ctx.cwd);
  }
  
  if (choice === "Allow for Project") {
    tempApprovals.push(command);
    persistState();
    intentDetector?.recordApproval(command);  // ADD THIS
    if (persistAllowToProject(ctx.cwd, command) && reloadProjectConfig) {
      reloadProjectConfig(ctx.cwd);
    }
    trackLearningCommand(command, mergedConfig, tempApprovals, ctx.cwd);
  }
  
  return undefined;  // Allow
}
```

## Step 8: Update checkShellCall Calls (line ~1350)

In the `tool_call` event handler, update the `checkShellCommand` call:

```typescript
for (const cmd of cmdsToCheck) {
  const result = await checkShellCommand(
    cmd, 
    merged, 
    mode, 
    tool, 
    ctx, 
    tempApprovals,
    intentDetector,  // ADD THIS
    (cwd) => {
      const fresh = loadProjectConfig(cwd);
      if (fresh) projectConfig = fresh;
    }
  );
  // ... rest of code ...
}
```

## Step 9: Add /safe-shell Commands (line ~1600)

In the `/safe-shell` command handler, add new subcommands:

```typescript
case "intent-mode": {
  const targetMode = value.toLowerCase();
  if (!['sandbox', 'development', 'production', 'migration'].includes(targetMode)) {
    ctx.ui.notify(
      `Invalid mode "${targetMode}". Use: sandbox, development, production, or migration.`,
      "error",
    );
    return;
  }
  globalConfig.intentDetectionMode = targetMode as any;
  ctx.ui.notify(`Intent detection mode set to "${targetMode}"`, "info");
  return;
}

case "intent-status": {
  const stats = intentDetector?.getStats();
  const lines = [
    `Intent Detection: ${globalConfig.intentDetectionEnabled ? 'ON' : 'OFF'}`,
    `Mode: ${globalConfig.intentDetectionMode}`,
    stats ? `\nSession Stats:\n  Templates: ${stats.totalTemplates}\n  Approvals: ${stats.totalApprovals}` : '',
    stats?.topTemplates.length ? `\nTop Templates:\n${stats.topTemplates.map(t => `  • ${t.template} (${t.count}x)`).join('\n')}` : '',
  ].filter(Boolean).join('\n');
  ctx.ui.notify(lines, "info");
  return;
}
```

## Step 10: Update System Prompt (line ~1500)

In the `before_agent_start` event, add intent detection info:

```typescript
pi.on("before_agent_start", async (_event, ctx) => {
  const mode = effectiveMode();
  const modeLabel = MODE_LABELS[mode];
  const approvals = tempApprovals.length;
  
  const intentInfo = globalConfig.intentDetectionEnabled 
    ? `\n  Intent Detection: ${globalConfig.intentDetectionMode} mode (auto-approves safe repetitive commands)`
    : '';

  const modeHint =
    `You are operating in ${modeLabel} bash security mode. ` +
    (mode === "block"
      ? "All bash commands are blocked. Use the available built-in tools (Read, Write, Edit, Grep, Find) or registered safe tools (run_tests, git_status, list_files)."
      : mode === "ask"
        ? `Each bash command requires user confirmation. You may ask the user to approve individual commands or switch modes via /safe-shell.${intentInfo}`
        : mode === "whitelist"
          ? `Only whitelisted bash patterns are allowed. Session has ${approvals} command approval(s). You may ask the user to approve additional commands via /safe-shell.${intentInfo}`
          : `⚠️ YOLO MODE: All commands allowed except denylist items. Use with extreme caution. Session has ${approvals} command approval(s).${intentInfo}`);

  return {
    systemPrompt: _event.systemPrompt + `\n\n## Safe Shell\n\n${modeHint}`,
  };
});
```

## Testing the Integration

After applying these changes:

1. Run `npm test` to ensure all tests pass
2. Start a pi session with the extension
3. Run a command like `grep "pattern" README.md` - should ask first time
4. Approve the command
5. Run `grep "API" README.md` - should auto-approve (same template)
6. Run `/safe-shell intent-status` to see session stats

## Rollback Plan

If issues arise, the intent detector can be disabled via config:

```json
{
  "intentDetectionEnabled": false
}
```

Or via command:
```
/safe-shell intent-mode off  # If implemented
```
