/**
 * AST Analyzer V2 — Proposed refactor of scoreCommand
 *
 * Key changes from v1:
 * 1. Use base command classification (extracted from intent-detector sets) — NOT
 *    classifyCommandSafety() which auto-promotes to Contextual on any shell operator
 * 2. Short-circuit Safe commands (return 0) — flags and paths don't matter
 * 3. Don't penalize home directory for read-only commands
 * 4. Only ADD score for genuinely dangerous patterns (rm -rf, chmod 777, etc.)
 * 5. Keep existing dangerous pattern detection (chained, RCE, exfil)
 *
 * Goals (from baseline.md):
 * - Reduce false positives from 59 to ≤ 18 (≥ 70% reduction)
 * - Keep false negatives ≤ 12 (no safety regression)
 * - Achieve ≥ 90% accuracy (189/210)
 */

import type { CommandAnalysis, RiskResult } from './ast-analyzer';

// ============================================================
// Inline code analysis (replicated from ast-analyzer.ts which doesn't export it)
// ============================================================
function analyzeInlineCodeLocal(code: string): { score: number; reasons: string[]; riskFactors: string[] } {
  const result = { score: 0, reasons: [] as string[], riskFactors: [] as string[] };
  
  if (/\b(rm\s+-rf\s+[/~\\]|dd\s+if=|mkfs|fdisk|parted|partprobe)/.test(code)) {
    result.score += 60;
    result.reasons.push('inline code contains destructive shell command');
    result.riskFactors.push('destructive_inline_code');
  }
  
  if (/\b(system|exec|execSync|spawn|spawnSync|subprocess)\s*[.(:]/i.test(code)) {
    result.score += 40;
    result.reasons.push('inline code calls system/exec');
    result.riskFactors.push('system_call');
  }
  
  if (/\b(urllib|requests|socket|https?|http\.get|axios|curl\s+http)\b/.test(code)) {
    result.score += 30;
    result.reasons.push('inline code contains network operations');
    result.riskFactors.push('network_inline_code');
  }
  
  if (/\b(curl|wget)\s+.*\|.*\b(bash|sh|zsh)\b/.test(code)) {
    result.score += 60;
    result.reasons.push('inline code contains remote code execution pattern');
    result.riskFactors.push('rce_inline_code');
  }
  
  if (/\b(os\.remove|os\.rmdir|os\.system)\b/.test(code)) {
    result.score += 50;
    result.reasons.push('inline code calls os.system/os.remove');
    result.riskFactors.push('os_system_call');
  }
  
  if (/\beval\s*\(/.test(code)) {
    result.score += 40;
    result.reasons.push('inline code contains nested eval');
    result.riskFactors.push('nested_eval');
  }
  
  if (/\b(atob|base64|b64decode)\b/.test(code)) {
    result.score += 30;
    result.reasons.push('inline code contains base64 decoding');
    result.riskFactors.push('obfuscated_code');
  }
  
  return result;
}

// ============================================================
// Command classification sets
// ============================================================
const SAFE_COMMANDS = new Set([
  'cat', 'head', 'tail', 'less', 'more', 'bat', 'nl',
  'grep', 'rg', 'ag', 'ack',
  'ls', 'find', 'stat', 'tree', 'dir',
  'wc', 'sort', 'uniq', 'cut', 'paste', 'join', 'tr', 'awk', 'sed',
  'pwd', 'cd', 'dirs', 'pushd', 'popd',
  'echo', 'printf',
  'git-status', 'git-log', 'git-diff', 'git-branch', 'git-show', 'git-remote',
  'date', 'time', 'whoami', 'hostname', 'uname', 'which', 'type',
  'node', 'python', 'python3', 'npm', 'pnpm', 'yarn', 'uv', 'cargo', 'go', 'rustc',
]);

// V2 addition: basic file operations are safe (recoverable from git)
const FILE_OPS = new Set([
  'cp', 'mv', 'mkdir', 'touch', 'ln', 'install', 'rsync', 'tee',
]);

const CONTEXTUAL_COMMANDS = new Set([
  'git-checkout', 'git-reset', 'git-rebase', 'git-merge', 'git-am',
  'npm', 'pnpm', 'yarn', 'pip', 'pip3', 'uv', 'bundle', 'cargo', 'go-get',
  'make', 'just', 'rake', 'gradle', 'mvn', 'npm-run', 'pnpm-run',
  'docker', 'docker-compose', 'podman',
  'curl', 'wget', 'ssh', 'scp', 'rsync',
  'psql', 'mysql', 'sqlite3', 'mongo', 'redis-cli',
  'jest', 'mocha', 'pytest', 'vitest', 'rspec',
  'chmod', 'chown', 'chgrp', 'setfacl',  // permission changes (contextual)
  'kill', 'killall', 'pkill',  // process control (contextual)
]);

const DANGEROUS_COMMANDS = new Set([
  'rm', 'rmdir', 'unlink', 'shred',
  'sudo', 'su', 'doas',
  'dd', 'mkfs', 'mkfs.ext4', 'mkfs.xfs', 'fdisk', 'parted', 'partprobe', 'format',
]);

// v2: chmod/chown/kill are contextual (common ops) — not inherently dangerous
// True danger comes from patterns (chmod 777, kill -9 1, etc.)

const EXTRA_SAFE_COMMANDS = new Set([
  'ps', 'top', 'htop', 'lsof', 'netstat', 'ss', 'ifconfig', 'ip',
  'df', 'du', 'free', 'uptime', 'arch', 'nproc',
  'file', 'md5sum', 'sha256sum', 'basename', 'dirname',
  'xargs',
  'true', 'false', 'test', '[',
  'basename', 'dirname', 'readlink', 'realpath',
]);

// ============================================================
// Classification enum
// ============================================================
type ClassifiedSafety = 'safe' | 'contextual' | 'dangerous';

function classifyBase(command: string): ClassifiedSafety {
  // Strip safe redirects before extracting base
  const stripped = command
    .replace(/\s*[012]?>?\/?dev\/null\b/g, '')
    .replace(/\s*>>?\s*\/tmp\/[^\s]*/g, '')
    .trim();
  
  const tokens = stripped.split(/\s+/).filter(t => t.length > 0);
  if (tokens.length === 0) return 'safe';

  // Skip leading env-var assignments (VAR=value)
  const cmdStart = tokens.findIndex(t => !/^[A-Z_][A-Z0-9_]*=/.test(t));
  const effectiveTokens = cmdStart >= 0 ? tokens.slice(cmdStart) : tokens;
  if (effectiveTokens.length === 0) return 'safe';

  let baseCommand = effectiveTokens[0].toLowerCase();

  // Strip path prefix (e.g., /usr/bin/rm -> rm)
  baseCommand = baseCommand.replace(/^.*\//, '');

  // Normalize git commands: "git status" -> "git-status"
  if (baseCommand === 'git' && effectiveTokens.length > 1) {
    const gitSubcommand = effectiveTokens[1].toLowerCase();
    const normalizedGit = `git-${gitSubcommand}`;
    // Safe git operations (recoverable, no remote)
    const SAFE_GIT = new Set([
      'git-status', 'git-log', 'git-diff', 'git-branch', 'git-show', 'git-remote',
      'git-add', 'git-commit', 'git-pull', 'git-fetch', 'git-stash', 'git-restore',
      'git-merge',  // Merge is recoverable (can reset)
    ]);
    if (SAFE_GIT.has(normalizedGit)) {
      return 'safe';
    }
    // Contextual git (can lose work with --force or wrong args)
    const CONTEXTUAL_GIT = new Set([
      'git-checkout', 'git-reset', 'git-rebase', 'git-am', 'git-push',
    ]);
    if (CONTEXTUAL_GIT.has(normalizedGit)) {
      return 'contextual';
    }
    // Unknown git command - treat as contextual
    return 'contextual';
  }

  // Normalize npm/pnpm/yarn: "npm test", "npm run build" -> "npm-test" (safe)
  // "npm install" -> "npm-install" (contextual)
  if (['npm', 'pnpm', 'yarn'].includes(baseCommand) && effectiveTokens.length > 1) {
    const sub = effectiveTokens[1].toLowerCase();
    const normalizedPkg = `${baseCommand}-${sub}`;
    // Safe subcommands (read-only, run scripts)
    const SAFE_PKG = new Set([
      'npm-test', 'npm-run', 'npm-start', 'npm-ls', 'npm-list', 'npm-outdated',
      'npm-view', 'npm-info', 'npm-search', 'npm-config', 'npm-version',
      'pnpm-test', 'pnpm-run', 'pnpm-start', 'pnpm-ls', 'pnpm-list',
      'yarn-test', 'yarn-run', 'yarn-start', 'yarn-list',
    ]);
    if (SAFE_PKG.has(normalizedPkg)) {
      return 'safe';
    }
    // Everything else (install, add, remove, publish) stays contextual
  }

  // Special case: rm -i is interactive (safe) — but only if no force/recursive flags
  if (baseCommand === 'rm' && effectiveTokens.includes('-i') &&
      !effectiveTokens.some(t => /^(-[rfR]+|--recursive|--force)$/.test(t))) {
    return 'safe';
  }
  
  if (DANGEROUS_COMMANDS.has(baseCommand)) return 'dangerous';
  if (FILE_OPS.has(baseCommand)) return 'safe';
  if (CONTEXTUAL_COMMANDS.has(baseCommand)) return 'contextual';
  if (SAFE_COMMANDS.has(baseCommand)) return 'safe';
  if (EXTRA_SAFE_COMMANDS.has(baseCommand)) return 'safe';
  
  // Default unknown commands to contextual (require approval)
  return 'contextual';
}

// ============================================================
// System paths that are dangerous for write operations
// ============================================================
const SYSTEM_WRITE_PATHS = [
  '/etc',
  '/usr',
  '/bin',
  '/sbin',
  '/boot',
  '/var',  // system logs, system state
  '/root',  // root's home
];

// ============================================================
// Patterns that are ALWAYS dangerous regardless of base command
// ============================================================
const ALWAYS_DANGEROUS_PATTERNS: { pattern: RegExp; reason: string; risk: string; bonus: number }[] = [
  // Network to pipe to execution (curl | bash) — CRITICAL
  {
    pattern: /\b(curl|wget)\b.*\|.*\b(bash|sh|zsh|node|python|ruby|perl)\b/i,
    reason: 'network to interpreter pipeline',
    risk: 'remote_code_execution',
    bonus: 50,
  },
  // Archive piped to network tool (CRITICAL)
  {
    pattern: /\btar\b.*\|.*\b(curl|wget|nc)\b/i,
    reason: 'archive piped to network tool',
    risk: 'data_exfiltration',
    bonus: 50,
  },
  // base64 decode piped to shell (CRITICAL)
  {
    pattern: /\bbase64\b.*-d.*\|.*\b(bash|sh)\b/i,
    reason: 'base64 decode piped to shell',
    risk: 'obfuscated_execution',
    bonus: 50,
  },
  // nc -e (netcat exec / reverse shell) (CRITICAL)
  {
    pattern: /\bnc\b.*-e/,
    reason: 'netcat with -e (reverse shell)',
    risk: 'reverse_shell',
    bonus: 50,
  },
  // Download-then-execute (wget -O file && bash file, curl -o file && bash file)
  {
    pattern: /\b(wget|curl)\b.*(-O\b|-output-document\b|-o\b).*(&&|\|\|).*\b(bash|sh|zsh|node|python)\b/i,
    reason: 'download then execute',
    risk: 'remote_code_execution',
    bonus: 30,
  },
  // Data exfiltration with secret keywords
  {
    pattern: /\b(cat|tail|head)\b.*(\.env|\.ssh|\.pem|\.key|secret|credential).*\|.*\b(curl|wget|nc)\b/i,
    reason: 'potential data exfiltration',
    risk: 'data_exfiltration',
    bonus: 30,
  },
  // Command substitution with destructive command
  {
    pattern: /\$\([^)]*rm[^)]*\)/,
    reason: 'command substitution with rm',
    risk: 'obfuscated_destruction',
    bonus: 30,
  },
  {
    pattern: /`[^`]*rm[^`]*`/,
    reason: 'backtick substitution with rm',
    risk: 'obfuscated_destruction',
    bonus: 30,
  },
  // Fork bomb
  {
    pattern: /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/,
    reason: 'fork bomb pattern',
    risk: 'fork_bomb',
    bonus: 100,
  },
  // Disk wipe (dd to block device)
  {
    pattern: /\bdd\b.*\bof=\/dev\/(sd|hd|nvme|vd|mmcblk)/i,
    reason: 'dd writing to block device',
    risk: 'disk_wipe',
    bonus: 30,
  },
  // No-preserve-root with rm
  {
    pattern: /\brm\b.*--no-preserve-root/,
    reason: 'rm with --no-preserve-root',
    risk: 'system_destruction',
    bonus: 30,
  },
  // World-writable permissions (DANGER 51+, not critical)
  {
    pattern: /\bchmod\b.*\s777\b/,
    reason: 'chmod 777 (world-writable)',
    risk: 'insecure_permissions',
    bonus: 26,
  },
  {
    pattern: /\bchmod\b.*-R.*\s777\b/,
    reason: 'recursive chmod 777',
    risk: 'insecure_permissions',
    bonus: 26,
  },
  // chmod -R on system paths
  {
    pattern: /\bchmod\b.*-R.*\s*(\/etc\/|\/usr\/|\/bin\/|\/sbin\/|\/boot\/)/,
    reason: 'recursive chmod on system path',
    risk: 'system_permission_change',
    bonus: 30,
  },
  // chmod -R on root (just /) - requires whitespace before /
  {
    pattern: /\bchmod\b.*-R.*\s+\/(\s|$|;|&|\|)/,
    reason: 'recursive chmod on root',
    risk: 'system_permission_change',
    bonus: 30,
  },
  // chown -R on system paths
  {
    pattern: /\bchown\b.*-R.*\s*(\/etc\/|\/usr\/|\/bin\/|\/sbin\/|\/boot\/)/,
    reason: 'recursive chown on system path',
    risk: 'system_ownership_change',
    bonus: 30,
  },
  // rm -rf on root or home (CRITICAL — must reach 81+)
  // Matches / or ~ or $HOME as the TARGET, even when followed by other commands
  {
    pattern: /\brm\b.*-rf.*\s+(\/|~|\$HOME)(\s|$|;|&|\|)/,
    reason: 'rm -rf on root or home',
    risk: 'system_destruction',
    bonus: 30,
  },
  // rm -rf followed by / or ~ (no whitespace variant)
  {
    pattern: /\brm\b.*-rf.*(\/|~|\$HOME)(\s|$|;|&|\|)/,
    reason: 'rm -rf on critical path',
    risk: 'system_destruction',
    bonus: 30,
  },
  // rm -rf on a top-level user path (Downloads, Documents, Desktop) — CRITICAL
  {
    pattern: /\brm\b.*-rf.*\/(Users|home)\/\w+\/(Downloads|Documents|Desktop)\b/,
    reason: 'rm -rf on user data directory',
    risk: 'user_data_destruction',
    bonus: 30,
  },
  // Sudo + dangerous command
  {
    pattern: /\bsudo\b.*\b(rm|chmod|chown|dd|mkfs|fdisk|shred)\b/,
    reason: 'sudo with destructive command',
    risk: 'privilege_escalation',
    bonus: 30,
  },
  // git push --force (CRITICAL — destructive)
  {
    pattern: /\bgit\b.*\bpush\b.*--force/,
    reason: 'git push --force',
    risk: 'force_push',
    bonus: 30,
  },
  // git reset --hard (CRITICAL — destructive)
  {
    pattern: /\bgit\b.*\breset\b.*--hard/,
    reason: 'git reset --hard',
    risk: 'destructive_reset',
    bonus: 30,
  },
];

// ============================================================
// Base score by classification
// ============================================================
const BASE_SCORE: Record<ClassifiedSafety, number> = {
  safe: 0,
  contextual: 25,
  dangerous: 70,
};

// ============================================================
// V2 scoreCommand
// ============================================================
export function scoreCommandV2(analysis: CommandAnalysis): RiskResult {
  const reasons: string[] = [];
  const riskFactors: string[] = [];
  let score = 0;

  // 0. Check for ALWAYS-dangerous patterns first (applies even to "safe" commands)
  //    This catches things like `echo "x" > /etc/passwd`, `cat X | curl`, etc.
  for (const pat of ALWAYS_DANGEROUS_PATTERNS) {
    if (pat.pattern.test(analysis.command)) {
      score += pat.bonus;
      reasons.push(pat.reason);
      riskFactors.push(pat.risk);
    }
  }
  
  // 0a. System file overwrite via redirect (echo "x" > /etc/passwd)
  //     This is critical — even a "safe" command like echo is dangerous if
  //     it overwrites a system file
  if (/[>]\s*(\/etc\/|\/usr\/|\/bin\/|\/sbin\/|\/boot\/)/.test(analysis.command)) {
    score = Math.max(score, 85);
    if (!reasons.includes('redirect to system path')) {
      reasons.push('redirect to system path');
      riskFactors.push('system_overwrite');
    }
  }
  // 0a.2. chmod/chown -R on system paths
  if (/\b(chmod|chown|chgrp)\b.*-R.*\s*(\/etc\/|\/usr\/|\/bin\/|\/sbin\/|\/boot\/)/.test(analysis.command)) {
    score = Math.max(score, 85);
    reasons.push('recursive permission change on system path');
    riskFactors.push('system_permission_change');
  }
  // 0a.3. chown -R on system
  if (/\bchown\b.*-R.*\/etc/.test(analysis.command)) {
    score = Math.max(score, 85);
    reasons.push('chown -R on /etc');
    riskFactors.push('system_ownership_change');
  }
  
  // 0b. General data exfiltration: cat/tar/grep piped to network tool
  //     Lower bonus than secret-specific exfil, but still flags suspicious patterns
  const generalExfil = /\b(cat|tar|grep|find|head|tail)\b.*\|.*\b(curl|wget|nc|netcat)\b/i.test(analysis.command);
  if (generalExfil && !riskFactors.includes('data_exfiltration')) {
    // Higher bonus if reading sensitive files (passwd, shadow, hosts)
    const isSensitive = /\/etc\/(passwd|shadow|hosts|sudoers|hostname)/.test(analysis.command);
    // Also escalate if reading any /etc/ file
    const isEtc = /\/etc\//.test(analysis.command);
    if (isSensitive) {
      score = Math.max(score, 85);
      reasons.push('sensitive data piped to network tool');
      riskFactors.push('data_exfiltration');
    } else if (isEtc) {
      score = Math.max(score, 60);
      reasons.push('system file piped to network tool');
      riskFactors.push('potential_data_exfiltration');
    } else {
      score += 25;
      reasons.push('data piped to network tool');
      riskFactors.push('potential_data_exfiltration');
    }
  }
  
  // 0b.2. Force critical for known-critically-dangerous patterns
  // These must always reach 81+ regardless of base command
  const forceCritical = [
    /\b(curl|wget)\b.*\|.*\b(bash|sh|zsh|node|python|ruby|perl)\b/i,
    /\btar\b.*\|.*\b(curl|wget|nc)\b/i,
    /\bbase64\b.*-d.*\|.*\b(bash|sh)\b/i,
    /\bnc\b.*-e/,
    /\b(wget|curl)\b.*(-O\b|-output-document\b|-o\b).*(&&|\|\|).*\b(bash|sh|zsh|node|python)\b/i,
  ];
  for (const pat of forceCritical) {
    if (pat.test(analysis.command)) {
      score = Math.max(score, 85);
      if (!reasons.includes('network to interpreter pipeline') &&
          !reasons.includes('archive piped to network tool') &&
          !reasons.includes('base64 decode piped to shell') &&
          !reasons.includes('netcat with -e (reverse shell)') &&
          !reasons.includes('download then execute')) {
        // Re-classify the reason
        if (pat.source.includes('base64')) reasons.push('base64 decode piped to shell');
        else if (pat.source.includes('nc')) reasons.push('netcat with -e (reverse shell)');
        else if (pat.source.includes('tar')) reasons.push('archive piped to network tool');
        else if (pat.source.includes('wget') || pat.source.includes('curl')) reasons.push('download then execute');
        else reasons.push('network to interpreter pipeline');
        riskFactors.push('remote_code_execution');
      }
    }
  }
  
  // 1. Classify base command
  const safety = classifyBase(analysis.command);
  score += BASE_SCORE[safety];

  // 0c. Inline code with destructive content (CHECK BEFORE SAFE SHORT-CIRCUIT)
  if (analysis.inlineCode) {
    const inlineAnalysis = analyzeInlineCodeLocal(analysis.inlineCode);
    if (inlineAnalysis.score > 0) {
      score += inlineAnalysis.score;
      reasons.push(...inlineAnalysis.reasons);
      riskFactors.push(...inlineAnalysis.riskFactors);
    }
  }
  // Interpreter with -c flag: if the inline code is destructive, that's critical
  if (analysis.flags.includes('-c') || analysis.flags.includes('-e')) {
    if (analysis.executable && ['bash', 'sh', 'zsh', 'python', 'python3', 'ruby', 'perl', 'node'].includes(analysis.executable)) {
      const inlineIsDestructive = analysis.inlineCode &&
        /\b(rm|chmod|chown|dd|mkfs|sudo|curl|wget|eval|os\.system|subprocess|child_process)\b/.test(analysis.inlineCode);
      if (inlineIsDestructive) {
        score = Math.max(score, 85);
        reasons.push('inline code with destructive operation');
        riskFactors.push('inline_destructive');
      }
    }
  }

  if (safety === 'safe') {
    // Safe command — but check if it reads system paths (info disclosure)
    const touchesSystemPath = analysis.paths.some(p =>
      SYSTEM_WRITE_PATHS.some(sp => p === sp || p.startsWith(sp + '/'))
    );
    if (touchesSystemPath) {
      score = Math.max(score, 25);
      reasons.push('reading system path');
      riskFactors.push('system_path_read');
    }
    // Whole-system search paths (/, /*) — only penalize for non-search commands
    // find/ls on / is normal reconnaissance, no penalty
    // Also handle pipelines: if the command STARTS with find/ls, don't penalize
    const touchesRoot = analysis.paths.some(p => p === '/' || p === '/*');
    const startsWithSearch = /^\s*(find|ls)\b/.test(analysis.command);
    const isNormalSearch = analysis.executable === 'find' || analysis.executable === 'ls' || startsWithSearch;
    if (touchesRoot && !isNormalSearch) {
      score = Math.max(score, 25);
      reasons.push('searching from root');
      riskFactors.push('root_search');
    }
    // Python/Node with -c flag (inline code) — at least caution
    if (analysis.flags.includes('-c') || analysis.flags.includes('-e')) {
      if (analysis.executable && ['python', 'python3', 'ruby', 'perl', 'node', 'bash', 'sh', 'zsh'].includes(analysis.executable)) {
        score = Math.max(score, 25);
        reasons.push('interpreter with inline code');
        riskFactors.push('inline_code_caution');
      }
    }
    return finalize(score, reasons, riskFactors);
  }

  if (safety === 'contextual') {
    reasons.push('contextual command (depends on args)');
  } else {
    reasons.push('dangerous command (inherently destructive)');
    riskFactors.push('dangerous_command');
  }

  // 2. System path + dangerous command (small bonus only)
  const touchesSystemPath = analysis.paths.some(p =>
    SYSTEM_WRITE_PATHS.some(sp => p === sp || p.startsWith(sp + '/'))
  );
  if (touchesSystemPath && safety === 'dangerous') {
    score += 20;
    reasons.push('dangerous command on system path');
    riskFactors.push('system_path_dangerous');
  }

  // 3. Block device + dangerous command (mkfs, dd on /dev/sd*)
  const touchesBlockDevice = analysis.paths.some(p =>
    /^\/dev\/(sd|hd|nvme|vd|mmcblk)/.test(p)
  );
  if (touchesBlockDevice) {
    score = Math.max(score, 85);
    reasons.push('operation on block device');
    riskFactors.push('block_device_operation');
  }

  // 4. Inline code with destructive content (already handled above, keep for non-safe commands)

  return finalize(score, reasons, riskFactors);
}

function finalize(score: number, reasons: string[], riskFactors: string[]): RiskResult {
  // Clamp score to 0-100
  score = Math.min(100, Math.max(0, score));
  const level = score <= 20 ? 'safe' : score <= 50 ? 'caution' : score <= 80 ? 'danger' : 'critical';
  return { score, level: level as RiskResult['level'], reasons, riskFactors: [...new Set(riskFactors)] };
}
