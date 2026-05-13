/**
 * AST-based shell command analyzer for pi-safe-shell
 * 
 * Inspired by sh-guard's semantic analysis approach, but implemented from scratch
 * in TypeScript with MIT license.
 * 
 * Three-layer pipeline:
 * 1. Parse - tree-sitter-bash → AST
 * 2. Analyze - Extract intent, targets, flags, risk factors
 * 3. Score - Calculate 0-100 risk score
 */

import Parser from 'web-tree-sitter';
import { readFileSync } from 'fs';
import { join } from 'path';

// ============================================================
// Types
// ============================================================

export enum Intent {
  Info = 'info',           // ls, pwd, date
  Read = 'read',           // cat, less, head
  Write = 'write',         // echo >, cp, mv
  Delete = 'delete',       // rm, truncate
  Execute = 'execute',     // node, python, bash -c
  Network = 'network',     // curl, wget, ssh
  Privilege = 'privilege', // sudo, chmod, chown
  Search = 'search',       // grep, find
  ProcessControl = 'process', // kill, pkill
  GitMutation = 'git',     // git commit, reset
}

export interface CommandAnalysis {
  command: string;
  executable?: string;
  args: string[];
  flags: string[];
  hasPipe: boolean;
  hasRedirect: boolean;
  paths: string[];
  intent: Intent[];
}

export interface RiskResult {
  score: number;  // 0-100
  level: 'safe' | 'caution' | 'danger' | 'critical';
  reasons: string[];
  riskFactors: string[];
}

// ============================================================
// Parser initialization
// ============================================================

let parser: Parser | null = null;
let bashLang: Parser.Language | null = null;
let isInitialized = false;

export async function initParser(): Promise<void> {
  if (isInitialized) return;
  
  await Parser.init();
  bashLang = await Parser.Language.load(
    readFileSync(join(__dirname, 'tree-sitter-bash.wasm'))
  );
  parser = new Parser();
  parser.setLanguage(bashLang);
  isInitialized = true;
}

export function isParserInitialized(): boolean {
  return isInitialized;
}

// ============================================================
// Command intent mapping
// ============================================================

const COMMAND_INTENTS: Record<string, Intent> = {
  // Info commands
  'ls': Intent.Info,
  'pwd': Intent.Info,
  'date': Intent.Info,
  'time': Intent.Info,
  'whoami': Intent.Info,
  'hostname': Intent.Info,
  'uname': Intent.Info,
  'echo': Intent.Info,
  
  // Read commands
  'cat': Intent.Read,
  'less': Intent.Read,
  'more': Intent.Read,
  'head': Intent.Read,
  'tail': Intent.Read,
  'wc': Intent.Read,
  
  // Search commands
  'grep': Intent.Search,
  'find': Intent.Search,
  'locate': Intent.Search,
  
  // Write commands
  'cp': Intent.Write,
  'mv': Intent.Write,
  'touch': Intent.Write,
  'mkdir': Intent.Write,
  
  // Delete commands
  'rm': Intent.Delete,
  'rmdir': Intent.Delete,
  'truncate': Intent.Delete,
  
  // Network commands
  'curl': Intent.Network,
  'wget': Intent.Network,
  'ssh': Intent.Network,
  'scp': Intent.Network,
  'rsync': Intent.Network,
  
  // Privilege commands
  'sudo': Intent.Privilege,
  'su': Intent.Privilege,
  'chmod': Intent.Privilege,
  'chown': Intent.Privilege,
  'chgrp': Intent.Privilege,
  
  // Execute commands
  'node': Intent.Execute,
  'python': Intent.Execute,
  'python3': Intent.Execute,
  'bash': Intent.Execute,
  'sh': Intent.Execute,
  'zsh': Intent.Execute,
  'exec': Intent.Execute,
  
  // Process control
  'kill': Intent.ProcessControl,
  'pkill': Intent.ProcessControl,
  'killall': Intent.ProcessControl,
  
  // Git
  'git': Intent.GitMutation,
};

// ============================================================
// AST Analysis
// ============================================================

export function analyzeCommand(command: string): CommandAnalysis {
  if (!parser || !bashLang) {
    throw new Error('Parser not initialized. Call initParser() first.');
  }
  
  const tree = parser.parse(command);
  const result: CommandAnalysis = {
    command,
    executable: undefined,
    args: [],
    flags: [],
    hasPipe: false,
    hasRedirect: false,
    paths: [],
    intent: []
  };
  
  function walk(node: Parser.SyntaxNode): void {
    // Extract command name
    if (node.type === 'command_name') {
      result.executable = node.text;
    }
    
    // Extract flags
    if (node.type === 'flag') {
      result.flags.push(node.text);
    }
    
    // Extract word arguments and detect paths
    if (node.type === 'word' && !node.text.startsWith('-')) {
      result.args.push(node.text);
      
      // Detect paths
      if (node.text.startsWith('/') || 
          node.text.startsWith('./') || 
          node.text.startsWith('~') || 
          node.text.includes('/')) {
        result.paths.push(node.text);
      }
    }
    
    // Detect pipelines
    if (node.type === 'pipeline') {
      result.hasPipe = true;
    }
    
    // Detect redirects
    if (node.type === 'redirect') {
      result.hasRedirect = true;
    }
    
    // Recurse into children
    for (const child of node.children) {
      walk(child);
    }
  }
  
  walk(tree.rootNode);
  
  // Determine intent from executable
  if (result.executable) {
    const baseName = result.executable.split('/').pop() || result.executable;
    const intent = COMMAND_INTENTS[baseName];
    if (intent) {
      result.intent = [intent];
    } else {
      // Default to Execute for unknown commands
      result.intent = [Intent.Execute];
    }
  }
  
  return result;
}

// ============================================================
// Risk Scoring (inspired by sh-guard, our own implementation)
// ============================================================

const INTENT_WEIGHTS: Record<Intent, number> = {
  [Intent.Info]: 0,
  [Intent.Search]: 5,
  [Intent.Read]: 10,
  [Intent.Write]: 20,
  [Intent.GitMutation]: 25,
  [Intent.Execute]: 30,
  [Intent.Network]: 35,
  [Intent.Delete]: 40,
  [Intent.Privilege]: 50,
  [Intent.ProcessControl]: 45,
};

const DANGEROUS_FLAGS: Record<string, number> = {
  '-r': 20,
  '-R': 20,
  '-rf': 25,
  '-fr': 25,
  '-f': 15,
  '--force': 15,
  '--force-with-lease': 10,
  '--no-preserve': 10,
  '--no-preserve-root': 30,
};

const CRITICAL_COMMANDS = [
  'dd',
  'mkfs',
  'mkfs.ext4',
  'mkfs.xfs',
  'fdisk',
  'parted',
  'partprobe',
];

const SYSTEM_PATHS = [
  '/',
  '/etc',
  '/usr',
  '/bin',
  '/sbin',
  '/var',
  '/boot',
  '/dev',
  '/proc',
  '/sys',
];

const HOME_INDICATORS = ['~', '$HOME'];

export function scoreCommand(analysis: CommandAnalysis): RiskResult {
  const reasons: string[] = [];
  const riskFactors: string[] = [];
  let score = 0;
  
  // 1. Intent weight (base score)
  const intent = analysis.intent[0] || Intent.Execute;
  score += INTENT_WEIGHTS[intent] || 20;
  
  // 2. Dangerous flags
  for (const flag of analysis.flags) {
    if (DANGEROUS_FLAGS[flag]) {
      score += DANGEROUS_FLAGS[flag];
      reasons.push(`dangerous flag: ${flag}`);
      
      if (flag === '-r' || flag === '-R' || flag === '-rf' || flag === '-fr') {
        riskFactors.push('recursive_operation');
      }
      if (flag === '-f' || flag === '--force') {
        riskFactors.push('force_flag');
      }
    }
  }
  
  // 3. Path scope analysis
  for (const path of analysis.paths) {
    // System root paths
    if (SYSTEM_PATHS.some(sysPath => path.startsWith(sysPath + '/') || path === sysPath)) {
      score += 30;
      reasons.push('targeting system root');
      riskFactors.push('system_path');
    }
    // Home directory
    else if (HOME_INDICATORS.some(indicator => path.startsWith(indicator))) {
      score += 20;
      reasons.push('targeting home directory');
      riskFactors.push('home_directory');
    }
    // Temp directories (safer)
    else if (path.startsWith('/tmp') || path.startsWith('/var/tmp')) {
      score += 5;
    }
    // Project paths (relative, safer)
    else if (path.startsWith('./') || !path.startsWith('/')) {
      score += 10;
    }
  }
  
  // 4. Pipeline detection
  if (analysis.hasPipe) {
    // Check for network-to-execution pattern (curl | bash)
    if (analysis.executable === 'curl' || analysis.executable === 'wget') {
      score += 40;
      reasons.push('network to pipe');
      riskFactors.push('remote_code_execution');
    }
    // Check for data exfiltration pattern (cat .env | curl)
    if (analysis.executable === 'cat' || analysis.executable === 'tail') {
      const hasSecretFile = analysis.args.some(arg => 
        arg.includes('.env') || 
        arg.includes('.ssh') || 
        arg.includes('secret') ||
        arg.includes('credential')
      );
      if (hasSecretFile) {
        score += 50;
        reasons.push('potential data exfiltration');
        riskFactors.push('data_exfiltration');
      }
    }
  }
  
  // 5. Redirect detection
  if (analysis.hasRedirect) {
    // Check for redirect to system paths
    const hasSystemRedirect = analysis.paths.some(path =>
      SYSTEM_PATHS.some(sysPath => path.startsWith(sysPath))
    );
    if (hasSystemRedirect) {
      score += 25;
      reasons.push('redirect to system path');
      riskFactors.push('system_write');
    }
  }
  
  // 6. Critical commands
  const commandWords = analysis.command.split(/\s+/);
  for (const critical of CRITICAL_COMMANDS) {
    if (commandWords.some(word => word === critical || word.startsWith(critical + '.'))) {
      score += 50;
      reasons.push('critical command detected');
      riskFactors.push('critical_command');
      break;
    }
  }
  
  // 7. Special dangerous patterns
  // Fork bomb
  if (analysis.command.includes(':(){ :|:& };:')) {
    score += 100;
    reasons.push('fork bomb pattern detected');
    riskFactors.push('fork_bomb');
  }
  
  // Sudo with dangerous command
  if (analysis.executable === 'sudo') {
    const firstArg = analysis.args[0];
    if (firstArg && CRITICAL_COMMANDS.includes(firstArg)) {
      score += 30;
      reasons.push('sudo with critical command');
      riskFactors.push('privilege_escalation');
    }
  }
  
  // 8. rm -rf patterns
  if (analysis.executable === 'rm') {
    const hasRecursive = analysis.flags.some(f => f === '-r' || f === '-R' || f === '-rf');
    const hasForce = analysis.flags.some(f => f === '-f' || f === '-rf');
    
    if (hasRecursive && hasForce) {
      // Check target
      const hasDangerousTarget = analysis.paths.some(path =>
        path === '/' || 
        path === '/etc' || 
        path.startsWith('~') ||
        path.startsWith('$HOME')
      );
      
      if (hasDangerousTarget) {
        score += 40;
        reasons.push('rm -rf with dangerous target');
        riskFactors.push('recursive_delete_critical');
      }
    }
  }
  
  // Clamp score to 0-100
  score = Math.min(100, Math.max(0, score));
  
  // Determine risk level
  const level = score <= 20 ? 'safe' : score <= 50 ? 'caution' : score <= 80 ? 'danger' : 'critical';
  
  // Add intent to reasons if it's the primary factor
  if (score <= 20 && intent !== Intent.Info) {
    reasons.unshift(`${intent} operation`);
  }
  
  return {
    score,
    level,
    reasons,
    riskFactors
  };
}

// ============================================================
// Convenience functions
// ============================================================

export function classifyCommand(command: string): RiskResult {
  const analysis = analyzeCommand(command);
  return scoreCommand(analysis);
}

export function getRiskLevelDescription(level: string): string {
  switch (level) {
    case 'safe':
      return 'Auto-execute: Command is safe to run';
    case 'caution':
      return 'Ask user: Command has minor risks';
    case 'danger':
      return 'Warn user: Command has significant risks';
    case 'critical':
      return 'Block: Command is highly dangerous';
    default:
      return 'Unknown risk level';
  }
}
