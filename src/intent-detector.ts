/**
 * Intent Detection Engine for pi-safe-shell
 * 
 * Multi-layer intent analysis:
 * 1. Command taxonomy (safe/contextual/dangerous)
 * 2. Path classification (project/user/system/root)
 * 3. Template abstraction with variable slots
 * 4. Session learning with auto-approve thresholds
 * 
 * Design principles:
 * - Graceful degradation: if any layer fails, fall back to "ask"
 * - Transparency: always explain WHY a decision was made
 * - User sovereignty: user can always override, system learns from overrides
 * - Progressive trust: start conservative, earn auto-approve through consistency
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join, resolve, relative } from 'path';
import { homedir } from 'os';

// ============================================================
// Types
// ============================================================

/**
 * Command safety classification
 */
export enum CommandSafety {
  Safe = 'safe',           // Read-only, non-destructive (grep, cat, ls, git status)
  Contextual = 'contextual', // Depends on args (git checkout, npm install, docker run)
  Dangerous = 'dangerous',   // Inherently destructive (rm, chmod, sudo, >)
}

/**
 * Path safety classification
 */
export enum PathSafety {
  ProjectSafe = 'PROJECT_SAFE',      // Within project root
  UserSpace = 'USER_SPACE',          // ~/Documents, ~/Code
  System = 'SYSTEM',                 // /etc, /usr, /bin
  RootDangerous = 'ROOT_DANGEROUS',  // / root
  Unknown = 'UNKNOWN',               // Cannot classify
}

/**
 * Template slot types for command abstraction
 */
export enum SlotType {
  String = '[STRING]',       // Quoted strings, search patterns
  Number = '[NUMBER]',       // Numeric arguments
  Path = '[PATH]',           // File/directory paths
  Identifier = '[IDENTIFIER]', // Variable names, branch names
  Flag = '[FLAG]',           // Command flags
}

/**
 * Abstracted command template
 */
export interface CommandTemplate {
  baseCommand: string;       // e.g., "grep"
  slots: SlotType[];         // e.g., [STRING, PATH]
  rawTemplate: string;       // e.g., "grep [STRING] [PATH]"
}

/**
 * Session approval tracking
 */
export interface ApprovalRecord {
  count: number;
  lastApproved: number;      // Timestamp
  pathClassifications: Record<PathSafety, number>;  // Count per path type
}

/**
 * Path override configuration
 */
export interface PathOverride {
  path: string;
  classification: PathSafety;
}

/**
 * Intent detector configuration
 */
export interface IntentDetectorConfig {
  mode: 'sandbox' | 'development' | 'production' | 'migration';
  persistApprovals: boolean;
  scope: 'global' | 'per-project';
  pathOverrides: Record<string, PathSafety>;
  projectRoot: string;
}

/**
 * Intent detection result
 */
export interface IntentResult {
  shouldAutoApprove: boolean;
  reason: string;
  safety: CommandSafety;
  pathSafety: PathSafety;
  template?: CommandTemplate;
  approvalCount?: number;
}

// ============================================================
// Command Safety Taxonomy
// ============================================================

const SAFE_COMMANDS = new Set([
  // File reading
  'cat', 'head', 'tail', 'less', 'more', 'bat', 'nl',
  // Searching
  'grep', 'rg', 'ag', 'ack',
  // Listing
  'ls', 'find', 'stat', 'tree', 'dir',
  // Text processing
  'wc', 'sort', 'uniq', 'cut', 'paste', 'join', 'tr', 'awk', 'sed',
  // Navigation
  'pwd', 'cd', 'dirs', 'pushd', 'popd',
  // Output (without redirection)
  'echo', 'printf',
  // Git read operations
  'git-status', 'git-log', 'git-diff', 'git-branch', 'git-show', 'git-remote',
  // Info
  'date', 'time', 'whoami', 'hostname', 'uname', 'which', 'type',
  // Version checks
  'node', 'python', 'python3', 'npm', 'pnpm', 'yarn', 'uv', 'cargo', 'go', 'rustc',
]);

const CONTEXTUAL_COMMANDS = new Set([
  // Git mutations (safe with proper args, dangerous with force)
  'git-checkout', 'git-reset', 'git-rebase', 'git-merge', 'git-am',
  // Package managers (can run scripts)
  'npm', 'pnpm', 'yarn', 'pip', 'pip3', 'uv', 'bundle', 'cargo', 'go-get',
  // Build tools
  'make', 'just', 'rake', 'gradle', 'mvn', 'npm-run', 'pnpm-run',
  // Docker (depends on container)
  'docker', 'docker-compose', 'podman',
  // Network (read-only but external)
  'curl', 'wget', 'ssh', 'scp', 'rsync',
  // Database
  'psql', 'mysql', 'sqlite3', 'mongo', 'redis-cli',
  // Test runners
  'jest', 'mocha', 'pytest', 'vitest', 'rspec',
]);

const DANGEROUS_COMMANDS = new Set([
  // Deletion
  'rm', 'rmdir', 'unlink', 'shred',
  // Permission changes
  'chmod', 'chown', 'chgrp', 'setfacl',
  // Privilege escalation
  'sudo', 'su', 'doas',
  // Disk operations
  'dd', 'mkfs', 'mkfs.ext4', 'mkfs.xfs', 'fdisk', 'parted', 'partprobe', 'format',
  // Process control
  'kill', 'killall', 'pkill',
  // Archive with overwrite
  'tar', 'zip', 'gzip',
]);

// Dangerous flags that are ALWAYS dangerous (not context-dependent)
const DANGEROUS_FLAGS = new Set([
  '-rf', '-fr',  // Combined recursive+force is always dangerous
  '--no-preserve', '--no-preserve-root',
  '-exec', '-eval',                  // Code execution
]);

// ============================================================
// Path Classification
// ============================================================

const SYSTEM_PATHS = [
  '/', '/etc', '/usr', '/bin', '/sbin', '/var', '/boot', '/dev', '/proc', '/sys',
  '/Library', '/Applications', '/System',  // macOS
];

const USER_SPACE_PREFIXES = [
  '~/Documents', '~/Code', '~/Projects', '~/dev', '~/work',
  '~/Downloads', '~/Desktop', '~/Music', '~/Pictures',
];

export function classifyPath(path: string, projectRoot: string, overrides: Record<string, PathSafety> = {}): PathSafety {
  // Check overrides first
  for (const [overridePath, classification] of Object.entries(overrides)) {
    // Normalize both paths for comparison
    const normalizedOverride = overridePath.replace(/\/$/, '');  // Strip trailing slash
    const normalizedInput = path.replace(/\/$/, '');
    
    // Exact match or starts with (for directory overrides)
    if (normalizedInput === normalizedOverride || 
        normalizedInput.startsWith(normalizedOverride + '/') || 
        normalizedInput.startsWith(normalizedOverride + '\\')) {
      return classification;
    }
  }
  
  // Normalize path
  const normalized = path.replace(/^['"]|['"]$/g, '');  // Strip quotes
  
  // Check for root
  if (normalized === '/' || normalized === '\\') {
    return PathSafety.RootDangerous;
  }
  
  // Check for system paths
  for (const sysPath of SYSTEM_PATHS) {
    if (normalized === sysPath || normalized.startsWith(sysPath + '/') || normalized.startsWith(sysPath + '\\')) {
      return PathSafety.System;
    }
  }
  
  // Check for home directory (including variable references)
  if (normalized.startsWith('~') || 
      normalized.startsWith('$HOME') || 
      normalized.startsWith('${HOME}')) {
    // Check if it's in user space prefixes
    for (const prefix of USER_SPACE_PREFIXES) {
      const expandedPrefix = prefix.replace('~', homedir());
      const expandedPath = normalized.replace(/^~/, homedir());
      if (expandedPath.startsWith(expandedPrefix)) {
        return PathSafety.UserSpace;
      }
    }
    // Home directory but not in known safe subdirs - still user space
    return PathSafety.UserSpace;
  }
  
  // Check for project-relative paths
  const absolutePath = resolve(projectRoot, normalized);
  if (absolutePath.startsWith(projectRoot)) {
    return PathSafety.ProjectSafe;
  }
  
  // Default to unknown
  return PathSafety.Unknown;
}

// ============================================================
// Template Abstraction
// ============================================================

export function extractTemplate(command: string): CommandTemplate {
  // Tokenize while preserving quoted strings
  const tokens: string[] = [];
  let current = '';
  let inQuote: string | null = null;
  
  for (let i = 0; i < command.length; i++) {
    const char = command[i];
    
    if (inQuote) {
      current += char;
      if (char === inQuote) {
        tokens.push(current);
        current = '';
        inQuote = null;
      }
    } else if (char === '"' || char === "'") {
      inQuote = char;
      current += char;
    } else if (/\s/.test(char)) {
      if (current) {
        tokens.push(current);
        current = '';
      }
    } else {
      current += char;
    }
  }
  
  if (current) tokens.push(current);
  
  const baseCommand = tokens[0] || command;
  const slots: SlotType[] = [];
  const slotPlaceholders: string[] = [];
  
  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    
    // Check if it's a flag
    if (token.startsWith('-')) {
      slots.push(SlotType.Flag);
      slotPlaceholders.push(SlotType.Flag);
    }
    // Check if it's a number
    else if (/^\d+$/.test(token)) {
      slots.push(SlotType.Number);
      slotPlaceholders.push(SlotType.Number);
    }
    // Check if it's a quoted string
    else if ((token.startsWith('"') && token.endsWith('"')) ||
             (token.startsWith("'") && token.endsWith("'"))) {
      slots.push(SlotType.String);
      slotPlaceholders.push(SlotType.String);
    }
    // Check if it's a path
    else if (token.startsWith('/') || 
             token.startsWith('./') || 
             token.startsWith('~') ||
             token.includes('/') ||
             // Common file extensions even without path prefix
             /\.(md|txt|json|ts|js|py|rb|go|rs|yaml|yml|toml|xml|html|css|scss|sh|bash|zsh)$/.test(token)) {
      slots.push(SlotType.Path);
      slotPlaceholders.push(SlotType.Path);
    }
    // Default to identifier
    else {
      slots.push(SlotType.Identifier);
      slotPlaceholders.push(SlotType.Identifier);
    }
  }
  
  return {
    baseCommand,
    slots,
    rawTemplate: [baseCommand, ...slotPlaceholders].join(' '),
  };
}

export function templatesMatch(template1: CommandTemplate, template2: CommandTemplate): boolean {
  if (template1.baseCommand !== template2.baseCommand) return false;
  if (template1.slots.length !== template2.slots.length) return false;
  
  for (let i = 0; i < template1.slots.length; i++) {
    // Flags must match exactly in position
    if (template1.slots[i] === SlotType.Flag && template2.slots[i] === SlotType.Flag) {
      // Treat all flags as equivalent slots for matching purposes
      continue;
    }
    // Other slot types must match exactly
    if (template1.slots[i] !== template2.slots[i]) return false;
  }
  
  return true;
}

// ============================================================
// Command Safety Classification
// ============================================================

export function classifyCommandSafety(command: string): CommandSafety {
  const tokens = command.trim().split(/\s+/);
  const baseCommand = tokens[0].toLowerCase();
  
  // Normalize git commands: "git status" -> "git-status"
  const normalizedCommand = baseCommand === 'git' && tokens.length > 1
    ? `git-${tokens[1].toLowerCase()}`
    : baseCommand;
  
  // Check dangerous first (highest priority)
  if (DANGEROUS_COMMANDS.has(normalizedCommand)) {
    return CommandSafety.Dangerous;
  }
  
  // Check for dangerous flags that are ALWAYS dangerous (not context-dependent)
  for (const token of tokens) {
    if (DANGEROUS_FLAGS.has(token.toLowerCase())) {
      return CommandSafety.Dangerous;
    }
  }
  
  // Check for shell operators (indicates chaining/piping)
  if (command.includes('&&') || command.includes('||') || command.includes(';') || 
      command.includes('|') || command.includes('`') || command.includes('$(')) {
    return CommandSafety.Contextual;
  }
  
  // Check for redirections
  if (command.includes('>') || command.includes('<')) {
    return CommandSafety.Contextual;
  }
  
  // Check contextual
  if (CONTEXTUAL_COMMANDS.has(normalizedCommand)) {
    return CommandSafety.Contextual;
  }
  
  // Check safe
  if (SAFE_COMMANDS.has(normalizedCommand)) {
    return CommandSafety.Safe;
  }
  
  // Default to contextual for unknown commands
  return CommandSafety.Contextual;
}

// ============================================================
// Intent Detector Class
// ============================================================

export class IntentDetector {
  private config: IntentDetectorConfig;
  private sessionApprovals: Map<string, ApprovalRecord>;
  private projectRoot: string;
  
  constructor(config: IntentDetectorConfig) {
    this.config = config;
    this.projectRoot = config.projectRoot;
    this.sessionApprovals = new Map();
  }
  
  /**
   * Analyze a command and return intent detection result
   */
  analyze(command: string): IntentResult {
    // Step 1: Classify command safety
    const safety = classifyCommandSafety(command);
    
    // Step 2: Extract path and classify path safety
    const tokens = command.trim().split(/\s+/);
    const paths = tokens.filter(t => 
      t.startsWith('/') || t.startsWith('./') || t.startsWith('~') || t.includes('/')
    );
    
    let pathSafety = PathSafety.Unknown;
    for (const path of paths) {
      const classified = classifyPath(path, this.projectRoot, this.config.pathOverrides);
      // Use the most restrictive path classification
      if (classified === PathSafety.RootDangerous) {
        pathSafety = PathSafety.RootDangerous;
        break;
      } else if (classified === PathSafety.System && pathSafety !== PathSafety.RootDangerous) {
        pathSafety = PathSafety.System;
      } else if (classified === PathSafety.UserSpace && 
                 pathSafety !== PathSafety.RootDangerous && 
                 pathSafety !== PathSafety.System) {
        pathSafety = PathSafety.UserSpace;
      } else if (pathSafety === PathSafety.Unknown) {
        pathSafety = classified;
      }
    }
    
    // Step 3: Extract template
    const template = extractTemplate(command);
    
    // Step 4: Check session approvals for template match
    const approvalRecord = this.getApprovalRecord(template);
    
    // Step 5: Determine auto-approve based on mode and thresholds
    const shouldAutoApprove = this.shouldAutoApproveCommand(safety, pathSafety, approvalRecord);
    
    // Step 6: Build reason string
    const reason = this.buildReason(safety, pathSafety, approvalRecord, shouldAutoApprove);
    
    return {
      shouldAutoApprove,
      reason,
      safety,
      pathSafety,
      template,
      approvalCount: approvalRecord?.count,
    };
  }
  
  /**
   * Record an approval for a command
   */
  recordApproval(command: string): void {
    const template = extractTemplate(command);
    const templateKey = template.rawTemplate;
    
    const existing = this.sessionApprovals.get(templateKey);
    if (existing) {
      existing.count++;
      existing.lastApproved = Date.now();
      
      // Track path classification
      const paths = command.trim().split(/\s+/).filter(t => 
        t.startsWith('/') || t.startsWith('./') || t.startsWith('~') || t.includes('/')
      );
      for (const path of paths) {
        const pathSafety = classifyPath(path, this.projectRoot, this.config.pathOverrides);
        existing.pathClassifications[pathSafety] = (existing.pathClassifications[pathSafety] || 0) + 1;
      }
    } else {
      const paths = command.trim().split(/\s+/).filter(t => 
        t.startsWith('/') || t.startsWith('./') || t.startsWith('~') || t.includes('/')
      );
      const pathClassifications: Record<PathSafety, number> = {};
      for (const path of paths) {
        const pathSafety = classifyPath(path, this.projectRoot, this.config.pathOverrides);
        pathClassifications[pathSafety] = (pathClassifications[pathSafety] || 0) + 1;
      }
      
      this.sessionApprovals.set(templateKey, {
        count: 1,
        lastApproved: Date.now(),
        pathClassifications,
      });
    }
  }
  
  /**
   * Get approval record for a template
   */
  private getApprovalRecord(template: CommandTemplate): ApprovalRecord | undefined {
    const templateKey = template.rawTemplate;
    return this.sessionApprovals.get(templateKey);
  }
  
  /**
   * Determine if command should be auto-approved based on safety, path, and approval history
   */
  private shouldAutoApproveCommand(
    safety: CommandSafety,
    pathSafety: PathSafety,
    approvalRecord?: ApprovalRecord
  ): boolean {
    // Never auto-approve dangerous commands
    if (safety === CommandSafety.Dangerous) {
      return false;
    }
    
    // Never auto-approve system or root paths
    if (pathSafety === PathSafety.System || pathSafety === PathSafety.RootDangerous) {
      return false;
    }
    
    // Get threshold based on mode
    const threshold = this.getThreshold(safety, pathSafety);
    
    // Check if approval count meets threshold
    if (!approvalRecord || approvalRecord.count < threshold) {
      return false;
    }
    
    return true;
  }
  
  /**
   * Get approval threshold based on mode and safety classification
   */
  private getThreshold(safety: CommandSafety, pathSafety: PathSafety): number {
    // Base thresholds by mode
    const modeThresholds: Record<typeof this.config.mode, Record<CommandSafety, number>> = {
      sandbox: {
        [CommandSafety.Safe]: 1,
        [CommandSafety.Contextual]: 1,
        [CommandSafety.Dangerous]: 999,  // Never
      },
      development: {
        [CommandSafety.Safe]: 1,
        [CommandSafety.Contextual]: 2,
        [CommandSafety.Dangerous]: 999,
      },
      production: {
        [CommandSafety.Safe]: 2,
        [CommandSafety.Contextual]: 3,
        [CommandSafety.Dangerous]: 999,
      },
      migration: {
        [CommandSafety.Safe]: 2,
        [CommandSafety.Contextual]: 999,  // Always ask
        [CommandSafety.Dangerous]: 999,
      },
    };
    
    const baseThreshold = modeThresholds[this.config.mode][safety];
    
    // Adjust based on path safety
    if (pathSafety === PathSafety.UserSpace) {
      return baseThreshold + 1;  // Require one more approval for user space
    }
    
    return baseThreshold;
  }
  
  /**
   * Build human-readable reason string
   */
  private buildReason(
    safety: CommandSafety,
    pathSafety: PathSafety,
    approvalRecord: ApprovalRecord | undefined,
    shouldAutoApprove: boolean
  ): string {
    const parts: string[] = [];
    
    // Safety classification
    parts.push(`Command safety: ${safety}`);
    
    // Path classification
    parts.push(`Path: ${pathSafety}`);
    
    // Approval history
    if (approvalRecord) {
      parts.push(`Approved ${approvalRecord.count}x before`);
    }
    
    // Auto-approve decision
    if (shouldAutoApprove) {
      parts.push('AUTO-APPROVED (template match + threshold met)');
    } else {
      const reasons: string[] = [];
      if (safety === CommandSafety.Dangerous) reasons.push('dangerous command');
      if (pathSafety === PathSafety.System) reasons.push('system path');
      if (pathSafety === PathSafety.RootDangerous) reasons.push('root path');
      if (!approvalRecord || approvalRecord.count < this.getThreshold(safety, pathSafety)) {
        reasons.push(`threshold not met (${approvalRecord?.count || 0}/${this.getThreshold(safety, pathSafety)})`);
      }
      parts.push(`REQUIRES APPROVAL (${reasons.join(', ')})`);
    }
    
    return parts.join(' | ');
  }
  
  /**
   * Get session approval statistics
   */
  getStats(): { totalTemplates: number; totalApprovals: number; topTemplates: Array<{ template: string; count: number }> } {
    const totalTemplates = this.sessionApprovals.size;
    const totalApprovals = Array.from(this.sessionApprovals.values()).reduce((sum, r) => sum + r.count, 0);
    
    const topTemplates = Array.from(this.sessionApprovals.entries())
      .map(([template, record]) => ({ template, count: record.count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);
    
    return { totalTemplates, totalApprovals, topTemplates };
  }
  
  /**
   * Clear session approvals
   */
  clear(): void {
    this.sessionApprovals.clear();
  }
}

// ============================================================
// Factory function
// ============================================================

export function createIntentDetector(config: Partial<IntentDetectorConfig> & { projectRoot: string }): IntentDetector {
  const defaultConfig: IntentDetectorConfig = {
    mode: 'production',  // Most conservative default
    persistApprovals: false,
    scope: 'per-project',
    pathOverrides: {},
    projectRoot: config.projectRoot,
  };
  
  return new IntentDetector({ ...defaultConfig, ...config });
}
