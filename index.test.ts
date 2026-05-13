import { describe, it, expect } from "vitest";

function compilePatterns(patterns: string[]): RegExp[] {
  return patterns.map((p) => { try { return new RegExp(p); } catch { return /(?!)/; } });
}

function commandMatchesAny(command: string, patterns: RegExp[]): boolean {
  return patterns.some((p) => p.test(command));
}

function tokenize(s: string): string[] {
  return s.trim().split(/\s+/).map((t) => {
    if (t.length >= 2) {
      const first = t[0], last = t[t.length - 1];
      if ((first === '"' && last === '"') || (first === "'" && last === "'")) return t.slice(1, -1);
    }
    return t;
  });
}

function commandTokenMatch(command: string, patterns: string[]): boolean {
  const cmdTokens = tokenize(command);
  if (cmdTokens.length === 0) return false;
  return patterns.some((pattern) => {
    const patTokens = tokenize(pattern);
    if (patTokens.length === 0 || patTokens.length > cmdTokens.length) return false;
    for (let i = 0; i <= cmdTokens.length - patTokens.length; i++) {
      let matches = true;
      for (let j = 0; j < patTokens.length; j++) {
        if (cmdTokens[i + j] !== patTokens[j]) { matches = false; break; }
      }
      if (matches) return true;
    }
    return false;
  });
}

function mergeConfigs(global: any, project: any) {
  if (!project) return global;
  return { ...global, ...project, whitelist: project.whitelist ?? global.whitelist, denylist: project.denylist ?? global.denylist };
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 3) + "...";
}

describe("compilePatterns", () => {
  it("compiles valid patterns", () => {
    const p = compilePatterns(["^npm\\s+test$"]);
    expect(p[0].test("npm test")).toBe(true);
  });
  it("handles invalid patterns", () => {
    const p = compilePatterns(["(unclosed"]);
    expect(p[0].test("anything")).toBe(false);
  });
});

describe("tokenize", () => {
  it("splits by whitespace", () => { expect(tokenize("rm -rf /")).toEqual(["rm", "-rf", "/"]); });
  it("strips quotes", () => { expect(tokenize('rm "-rf" /')).toEqual(["rm", "-rf", "/"]); });
});

describe("commandTokenMatch", () => {
  const DL = ["rm -rf /", "sudo", "mkfs"];
  it("blocks exact matches", () => { expect(commandTokenMatch("rm -rf /", DL)).toBe(true); });
  it("blocks sudo", () => { expect(commandTokenMatch("sudo apt", DL)).toBe(true); });
  it("allows rm -rf /tmp", () => { expect(commandTokenMatch("rm -rf /tmp", DL)).toBe(false); });
  it("allows --with-sudo", () => { expect(commandTokenMatch("./configure --with-sudo", DL)).toBe(false); });
});

describe("truncate", () => {
  it("truncates long strings", () => { expect(truncate("hello world", 8)).toBe("hello..."); });
});

describe("Multi-tool gate: tool detection", () => {
  function getShellInfo(toolName: string, input: Record<string, unknown>): { tool: string; command: string; commands?: string[] } | null {
    if (toolName === "bash") {
      const cmd = typeof input?.command === "string" ? input.command.trim() : "";
      return cmd ? { tool: "bash", command: cmd } : null;
    }
    if (toolName === "ctx_execute") {
      if (input?.language !== "shell") return null;
      const cmd = typeof input?.code === "string" ? input.code.trim() : "";
      return cmd ? { tool: "ctx_execute", command: cmd } : null;
    }
    if (toolName === "interactive_shell") {
      const cmd = typeof input?.command === "string" ? input.command.trim() : "";
      if (cmd) return { tool: "interactive_shell", command: cmd };
      const spawn = input?.spawn as Record<string, unknown> | undefined;
      if (spawn?.prompt && typeof spawn.prompt === "string") return { tool: "interactive_shell", command: spawn.prompt.trim() };
      return { tool: "interactive_shell", command: "(interactive session)" };
    }
    if (toolName === "ctx_batch_execute") {
      const cmds = input?.commands;
      if (!Array.isArray(cmds)) return null;
      const extracted = cmds.map((c: any) => typeof c?.command === "string" ? c.command.trim() : "").filter(Boolean);
      return extracted.length > 0 ? { tool: "ctx_batch_execute", command: extracted.join(" ; "), commands: extracted } : null;
    }
    return null;
  }

  it("detects bash", () => { expect(getShellInfo("bash", { command: "ls" })?.tool).toBe("bash"); });
  it("detects ctx_execute shell", () => { expect(getShellInfo("ctx_execute", { language: "shell", code: "ls" })?.tool).toBe("ctx_execute"); });
  it("skips ctx_execute non-shell", () => { expect(getShellInfo("ctx_execute", { language: "javascript", code: "x" })).toBeNull(); });
  it("detects interactive_shell", () => { expect(getShellInfo("interactive_shell", { command: "ls" })?.tool).toBe("interactive_shell"); });
  it("detects spawn prompt", () => { expect(getShellInfo("interactive_shell", { spawn: { prompt: "fix" } })?.command).toBe("fix"); });
  it("detects idle session", () => { expect(getShellInfo("interactive_shell", {})?.command).toBe("(interactive session)"); });
  it("detects batch", () => { expect(getShellInfo("ctx_batch_execute", { commands: [{ command: "ls" }] })?.commands).toEqual(["ls"]); });
  it("skips non-shell tools", () => { expect(getShellInfo("read", { path: "x" })).toBeNull(); });
});

describe("Multi-tool gate: command checking", () => {
  const DL = ["sudo", "rm -rf /"];
  const WL = ["^npm\\s+test$", "^ls$"];
  const OPS = /(&&|\|\||;)/;
  function check(cmd: string, mode: string): { block: boolean } | undefined {
    if (commandTokenMatch(cmd, DL)) return { block: true };
    if (mode === "block") return { block: true };
    if (mode === "whitelist") {
      if (OPS.test(cmd)) return { block: true };
      if (commandMatchesAny(cmd, compilePatterns(WL))) return undefined;
      return { block: true };
    }
    return { block: true };
  }
  it("denylist blocks", () => { expect(check("sudo x", "ask")?.block).toBe(true); });
  it("block mode blocks all", () => { expect(check("ls", "block")?.block).toBe(true); });
  it("whitelist allows", () => { expect(check("npm test", "whitelist")).toBeUndefined(); });
  it("batch blocks on first denylist", () => {
    const batch = ["echo", "sudo x", "ls"];
    let blocked = "";
    for (const cmd of batch) { if (commandTokenMatch(cmd, DL)) { blocked = cmd; break; } }
    expect(blocked).toBe("sudo x");
  });
});

describe("SHELL_EXEC_PATTERNS", () => {
  const patterns: { pattern: RegExp; label: string }[] = [
    { pattern: /execSync\s*\(/, label: "execSync" },
    { pattern: /execFileSync\s*\(/, label: "execFileSync" },
    { pattern: /[\.\w]exec\s*\(/, label: "exec" },
    { pattern: /[\.\w]*spawn(?:Sync)?\s*\(/, label: "spawn/spawnSync" },
    { pattern: /child_process/, label: "child_process" },
    { pattern: /shell\s*:\s*true/, label: "shell:true" },
    { pattern: /fork\s*\(/, label: "fork" },
    { pattern: /os\.system\s*\(/, label: "os.system" },
    { pattern: /os\.popen\s*\(/, label: "os.popen" },
    { pattern: /subprocess\.(?:run|call|check_output|Popen|check_call)\s*\(/, label: "subprocess" },
    { pattern: /shell\s*=\s*True/, label: "subprocess(shell=True)" },
  ];

  function detectShellOp(code: string): string | null {
    const match = patterns.find((p) => p.pattern.test(code));
    return match ? match.label : null;
  }

  it("detects execSync", () => {
    expect(detectShellOp('require("child_process").execSync("rm -rf /tmp")')).toBe("execSync");
  });
  it("detects execFileSync", () => {
    expect(detectShellOp('execFileSync("rm", ["-rf"])')).toBe("execFileSync");
  });
  it("detects exec", () => {
    expect(detectShellOp('cp.exec("rm -rf /tmp")')).toBe("exec");
  });
  it("detects spawn", () => {
    expect(detectShellOp('spawn("rm", ["-rf", "/tmp"])')).toBe("spawn/spawnSync");
  });
  it("detects spawnSync", () => {
    expect(detectShellOp('spawnSync("python3", ["script.py"])')).toBe("spawn/spawnSync");
  });
  it("detects child_process require", () => {
    expect(detectShellOp('const cp = require("child_process")')).toBe("child_process");
  });
  it("detects shell:true (spawn matches first since more specific)", () => {
    expect(detectShellOp('spawn("rm", { shell: true })')).toBe("spawn/spawnSync");
  });
  it("detects fork", () => {
    expect(detectShellOp('fork("child.js")')).toBe("fork");
  });
  it("detects os.system", () => {
    expect(detectShellOp('import os; os.system("rm -rf /tmp")')).toBe("os.system");
  });
  it("detects os.popen", () => {
    expect(detectShellOp('import os; os.popen("ls -la")')).toBe("os.popen");
  });
  it("detects subprocess.run", () => {
    expect(detectShellOp('subprocess.run("rm -rf /tmp", shell=True)')).toBe("subprocess");
  });
  it("detects subprocess.call", () => {
    expect(detectShellOp('subprocess.call("ls -la", shell=True)')).toBe("subprocess");
  });
  it("detects subprocess.check_output", () => {
    expect(detectShellOp('subprocess.check_output("whoami", shell=True)')).toBe("subprocess");
  });
  it("detects subprocess.Popen", () => {
    expect(detectShellOp('subprocess.Popen("rm -rf /tmp", shell=True)')).toBe("subprocess");
  });
  it("detects subprocess.check_call", () => {
    expect(detectShellOp('subprocess.check_call("git pull", shell=True)')).toBe("subprocess");
  });
  it("detects shell=True even without subprocess call", () => {
    expect(detectShellOp('run(cmd, shell=True)')).toBe("subprocess(shell=True)");
  });
  it("does NOT detect plain JS", () => {
    expect(detectShellOp('const x = 1; console.log(x)')).toBeNull();
  });
  it("does NOT detect plain Python", () => {
    expect(detectShellOp('import os; print(os.getcwd())')).toBeNull();
  });
  it("does NOT detect fs operations", () => {
    expect(detectShellOp('fs.rmSync("/tmp", { recursive: true })')).toBeNull();
  });
  it("does NOT detect shutil.rmtree", () => {
    expect(detectShellOp('shutil.rmtree("/tmp")')).toBeNull();
  });
  it("detects exec even in comments (heuristic is regex-based, not AST-aware)", () => {
    expect(detectShellOp('// execSync("rm -rf /")')).toBe("execSync");
  });
  it("detects first match in multi-op snippet", () => {
    const code = 'import subprocess\nimport os\nos.system("echo hi")\nsubprocess.run("ls", shell=True)\n';
    expect(detectShellOp(code)).toBe("os.system");
  });
  it("detects subprocess with extra whitespace", () => {
    expect(detectShellOp('subprocess.run  ("ls", shell=True)')).toBe("subprocess");
  });
});

describe("tryExtractShellCommand", () => {
  function tryExtractShellCommand(code: string): string | null {
    const execMatch = code.match(/[\.\w]*(?:execSync|exec|execFileSync|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen|check_call))\s*\(\s*([`"'])((?:[^`"'\\]|\\.)*?)\1/);
    if (execMatch) return execMatch[2];
    const spawnMatch = code.match(/[\.\w]*(?:spawn|spawnSync|fork)\s*\(\s*([`"'])((?:[^`"'\\]|\\.)*?)\1/);
    if (spawnMatch) return spawnMatch[2];
    return null;
  }

  it("extracts from execSync single quotes", () => {
    expect(tryExtractShellCommand("execSync('rm -rf /tmp')")).toBe("rm -rf /tmp");
  });
  it("extracts from execSync double quotes", () => {
    expect(tryExtractShellCommand('execSync("rm -rf /tmp")')).toBe("rm -rf /tmp");
  });
  it("extracts from execSync template literal", () => {
    expect(tryExtractShellCommand("execSync(`ls -la`)")).toBe("ls -la");
  });
  it("extracts from exec", () => {
    expect(tryExtractShellCommand('cp.exec("whoami")')).toBe("whoami");
  });
  it("extracts from spawn", () => {
    expect(tryExtractShellCommand('spawn("npm test")')).toBe("npm test");
  });
  it("returns null for variable command", () => {
    expect(tryExtractShellCommand('execSync(cmd)')).toBeNull();
  });
  it("extracts from template literal with placeholder (no expression evaluation)", () => {
    expect(tryExtractShellCommand("execSync(`rm -rf ${dir}`)")).toBe("rm -rf ${dir}");
  });
  it("returns null when no shell call", () => {
    expect(tryExtractShellCommand('console.log("hello")')).toBeNull();
  });
  it("extracts from os.system single quotes", () => {
    expect(tryExtractShellCommand("os.system('rm -rf /tmp')")).toBe("rm -rf /tmp");
  });
  it("extracts from os.system double quotes", () => {
    expect(tryExtractShellCommand('os.system("ls -la")')).toBe("ls -la");
  });
  it("extracts from os.popen", () => {
    expect(tryExtractShellCommand("os.popen('whoami')")).toBe("whoami");
  });
  it("extracts from subprocess.run", () => {
    expect(tryExtractShellCommand("subprocess.run('ls -la', shell=True)")).toBe("ls -la");
  });
  it("extracts from subprocess.call", () => {
    expect(tryExtractShellCommand("subprocess.call('echo hello', shell=True)")).toBe("echo hello");
  });
  it("extracts from subprocess.check_output", () => {
    expect(tryExtractShellCommand("subprocess.check_output('whoami', shell=True)")).toBe("whoami");
  });
  it("extracts from subprocess.Popen", () => {
    expect(tryExtractShellCommand("subprocess.Popen('rm -rf /tmp', shell=True)")).toBe("rm -rf /tmp");
  });
  it("extracts from subprocess.check_call", () => {
    expect(tryExtractShellCommand("subprocess.check_call('git pull', shell=True)")).toBe("git pull");
  });
  it("returns null for Python variable command", () => {
    expect(tryExtractShellCommand('os.system(cmd)')).toBeNull();
  });
  it("returns null for f-string", () => {
    expect(tryExtractShellCommand('os.system(f"rm -rf {dir}")')).toBeNull();
  });
  it("returns null for subprocess list args", () => {
    expect(tryExtractShellCommand('subprocess.run(["ls", "-la"])')).toBeNull();
  });
  it("handles empty quotes", () => {
    expect(tryExtractShellCommand('execSync("")')).toBe("");
  });
  it("handles multiline JS code", () => {
    const code = 'const cp = require("child_process");\ncp.execSync("rm -rf /tmp");';
    expect(tryExtractShellCommand(code)).toBe("rm -rf /tmp");
  });
  it("handles multiline Python code", () => {
    const code = 'import os\nos.system("rm -rf /tmp")\nprint("done")';
    expect(tryExtractShellCommand(code)).toBe("rm -rf /tmp");
  });
  it("handles whitespace between fn and parens", () => {
    expect(tryExtractShellCommand('os.system  ("ls")')).toBe("ls");
  });
});

describe("ctx_execute heuristic gate integration", () => {
  const patterns: { pattern: RegExp; label: string }[] = [
    { pattern: /execSync\s*\(/, label: "execSync" },
    { pattern: /[\.\w]*spawn(?:Sync)?\s*\(/, label: "spawn/spawnSync" },
    { pattern: /child_process/, label: "child_process" },
    { pattern: /os\.system\s*\(/, label: "os.system" },
    { pattern: /os\.popen\s*\(/, label: "os.popen" },
    { pattern: /subprocess\.(?:run|call|check_output|Popen|check_call)\s*\(/, label: "subprocess" },
    { pattern: /shell\s*=\s*True/, label: "subprocess(shell=True)" },
  ];

  function tryExtractShellCommand(code: string): string | null {
    const execMatch = code.match(/[\.\w]*(?:execSync|exec|execFileSync|os\.system|os\.popen|subprocess\.(?:run|call|check_output|Popen|check_call))\s*\(\s*([`"'])((?:[^`"'\\]|\\.)*?)\1/);
    if (execMatch) return execMatch[2];
    const spawnMatch = code.match(/[\.\w]*(?:spawn|spawnSync|fork)\s*\(\s*([`"'])((?:[^`"'\\]|\\.)*?)\1/);
    if (spawnMatch) return spawnMatch[2];
    return null;
  }

  function gateCtxExecute(language: string, code: string): "pass" | "detected-extracted" | "detected-generic" {
    if (language === "shell") return "detected-extracted";
    const matched = patterns.find((p) => p.pattern.test(code));
    if (!matched) return "pass";
    const extracted = tryExtractShellCommand(code);
    return extracted ? "detected-extracted" : "detected-generic";
  }

  it("passes pure JS", () => {
    expect(gateCtxExecute("javascript", 'console.log("hello")')).toBe("pass");
  });
  it("passes pure Python", () => {
    expect(gateCtxExecute("python", "print('hello')")).toBe("pass");
  });
  it("gates JS execSync + extracts", () => {
    expect(gateCtxExecute("javascript", "execSync('rm -rf /tmp')")).toBe("detected-extracted");
  });
  it("gates Python os.system + extracts", () => {
    expect(gateCtxExecute("python", "os.system('rm -rf /tmp')")).toBe("detected-extracted");
  });
  it("gates Python subprocess.run + extracts", () => {
    expect(gateCtxExecute("python", "subprocess.run('ls -la', shell=True)")).toBe("detected-extracted");
  });
  it("gates Python os.popen + extracts", () => {
    expect(gateCtxExecute("python", "os.popen('whoami')")).toBe("detected-extracted");
  });
  it("gates Python subprocess.Popen + extracts", () => {
    expect(gateCtxExecute("python", "subprocess.Popen('rm -rf /tmp', shell=True)")).toBe("detected-extracted");
  });
  it("gates JS spawn with shell:true (extracts first string arg)", () => {
    expect(gateCtxExecute("javascript", 'spawn("rm", ["-rf"], { shell: true })')).toBe("detected-extracted");
  });
  it("gates Python shell=True as generic", () => {
    expect(gateCtxExecute("python", 'subprocess.run(["rm", "-rf"], shell=True)')).toBe("detected-generic");
  });
  it("gates JS spawnSync + extracts", () => {
    expect(gateCtxExecute("javascript", "spawnSync('git status')")).toBe("detected-extracted");
  });
  it("gates Python variable cmd as generic", () => {
    expect(gateCtxExecute("python", "os.system(cmd)")).toBe("detected-generic");
  });
  it("gates JS template expr as extracted (placeholder is literal content)", () => {
    expect(gateCtxExecute("javascript", "execSync(`rm -rf ${dir}`)")).toBe("detected-extracted");
  });
  it("gates shell language ctx_execute", () => {
    expect(gateCtxExecute("shell", "rm -rf /tmp")).toBe("detected-extracted");
  });
  it("passes Python without shell patterns", () => {
    expect(gateCtxExecute("python", "import os; print(os.getcwd())")).toBe("pass");
  });
  it("passes JS fs operations", () => {
    expect(gateCtxExecute("javascript", 'fs.readFileSync("file.txt", "utf-8")')).toBe("pass");
  });
  it("passes Go code", () => {
    expect(gateCtxExecute("go", 'fmt.Println("hello")')).toBe("pass");
  });
  it("passes Python shutil.rmtree", () => {
    expect(gateCtxExecute("python", 'shutil.rmtree("/tmp")')).toBe("pass");
  });
});
