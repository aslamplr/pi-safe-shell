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

import * as TreeSitter from 'web-tree-sitter';
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
  CodeExecution = 'code_exec', // python -c, node -e, eval
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
  inlineCode?: string; // Code extracted from -c/-e flags
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

let parser: TreeSitter.Parser | null = null;
let bashLang: TreeSitter.Language | null = null;
let isInitialized = false;

export async function initParser(): Promise<void> {
  if (isInitialized) return;
  
  await TreeSitter.Parser.init();
  bashLang = await TreeSitter.Language.load(
    readFileSync(join(__dirname, 'tree-sitter-bash.wasm'))
  );
  parser = new TreeSitter.Parser();
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
  'ruby': Intent.Execute,
  'perl': Intent.Execute,
  'php': Intent.Execute,
  'bash': Intent.Execute,
  'sh': Intent.Execute,
  'zsh': Intent.Execute,
  'exec': Intent.Execute,
  'eval': Intent.CodeExecution,
  'xargs': Intent.Execute,
  
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
  
  function walk(node: TreeSitter.Node): void {
    // Extract command name
    if (node.type === 'command_name') {
      result.executable = node.text;
      // Don't walk children of command_name - they're just the command word
      return;
    }
    
    // Extract inline code from string nodes (after -c/-e flags)
    if (node.type === 'string_content') {
      // Check if parent string node's previous sibling was -c or -e flag
      const parentString = node.parent;
      if (parentString && parentString.type === 'string') {
        const prevSibling = parentString.previousSibling;
        if (prevSibling && (prevSibling.text === '-c' || prevSibling.text === '-e' || prevSibling.text === '-exec')) {
          result.inlineCode = node.text;
        }
      }
    }
    
    // Extract command substitution ($(cmd) or `cmd`)
    if (node.type === 'command_substitution') {
      if (!result.flags.includes('has_substitution')) {
        result.flags.push('has_substitution');
      }
      // The content of command substitution is the text inside $()
      // We store it for recursive analysis in scoring
      const innerText = node.text;
      if (innerText && innerText.length > 2) {
        // Strip the $() wrapper to get the actual command
        const commandText = innerText.startsWith('$(') 
          ? innerText.slice(2, -1) 
          : innerText;
        if (!result.args.includes(`__cmdsub__:${commandText}`)) {
          result.args.push(`__cmdsub__:${commandText}`);
        }
      }
    }
    
    // Extract variable expansions ($VAR, ${VAR})
    if (node.type === 'variable_expansion' || node.type === 'variable_name') {
      // For simple $VAR expansions, the variable name is the node text without $
      // For ${VAR} expansions, it's wrapped in ${}
      let varName = node.text;
      if (varName.startsWith('$')) varName = varName.slice(1);
      if (varName.startsWith('{')) varName = varName.slice(1, -1);
      
      if (!result.flags.includes(`uses_var:${varName}`)) {
        result.flags.push(`uses_var:${varName}`);
      }
    }
    
    // Extract heredoc body
    if (node.type === 'heredoc_body') {
      const bodyText = node.text;
      if (bodyText && bodyText.trim().length > 0) {
        if (!result.args.includes(`__heredoc__:${bodyText}`)) {
          result.args.push(`__heredoc__:${bodyText}`);
        }
      }
    }
    
    // Extract flags and arguments from word nodes
    // tree-sitter-bash doesn't distinguish flags from words, so we check manually
    if (node.type === 'word') {
      if (node.text.startsWith('-')) {
        // This is a flag (e.g., -l, -la, --long, -rf)
        // Handle combined short flags like -la or -rf
        if (node.text.startsWith('--')) {
          result.flags.push(node.text);
        } else if (node.text.startsWith('-')) {
          // Split combined flags: -la -> -l, -a; -rf -> -r, -f
          const flagChars = node.text.slice(1).split('');
          for (const char of flagChars) {
            result.flags.push('-' + char);
          }
        }
      } else {
        // Regular argument
        result.args.push(node.text);
        
        // Detect paths (including variable references)
        if (node.text.startsWith('/') || 
            node.text.startsWith('./') || 
            node.text.startsWith('~') || 
            node.text.startsWith('$') ||
            node.text.includes('/')) {
          result.paths.push(node.text);
        }
      }
    }
    
    // Detect pipelines
    if (node.type === 'pipeline') {
      result.hasPipe = true;
    }
    
    // Detect command chaining (&&, ||, ;)
    if (node.type === '&&' || node.type === '||' || node.type === ';') {
      result.hasPipe = true; // Treat chaining like piping for risk assessment
      if (!result.flags.includes('chained_command')) {
        result.flags.push('chained_command');
      }
    }
    
    // Detect redirects (file_redirect, heredoc_redirect, etc.)
    if (node.type.includes('redirect')) {
      result.hasRedirect = true;
      // Extract redirect target
      for (const child of node.children) {
        if (child.type === 'word' && (child.text.startsWith('/') || child.text.startsWith('./') || child.text.startsWith('~'))) {
          result.paths.push(child.text);
        }
      }
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
  [Intent.CodeExecution]: 55, // Higher base score for eval/exec patterns
};

const INTERPRETER_COMMANDS = [
  'python', 'python3', 'node', 'ruby', 'perl', 'php',
  'bash', 'sh', 'zsh', 'eval', 'exec', 'xargs'
];

/**
 * Analyze inline code string (from -c/-e flags) for dangerous patterns
 */
function analyzeInlineCode(code: string): { score: number; reasons: string[]; riskFactors: string[] } {
  const result = { score: 0, reasons: [] as string[], riskFactors: [] as string[] };
  
  // Check for destructive shell commands (works for sh -c, bash -c, and system/exec calls)
  if (/\b(rm\s+-rf\s+[/~\\]|dd\s+if=|mkfs|fdisk|parted|partprobe)/.test(code)) {
    result.score += 60;
    result.reasons.push('inline code contains destructive shell command');
    result.riskFactors.push('destructive_inline_code');
  }
  
  // Check for system/exec calls (Node.js, Python)
  if (/\b(system|exec|execSync|spawn|spawnSync)\s*\(/.test(code)) {
    result.score += 40;
    result.reasons.push('inline code calls system/exec');
    result.riskFactors.push('system_call');
  }
  
  // Check for network operations (Python urllib/requests, Node.js https, curl in shell)
  if (/\b(urllib|requests|socket|https?|http\.get|axios|curl\s+http)\b/.test(code)) {
    result.score += 30;
    result.reasons.push('inline code contains network operations');
    result.riskFactors.push('network_inline_code');
  }
  
  // Check for pipe to shell (bash -c "curl ... | bash")
  if (/\b(curl|wget)\s+.*\|.*\b(bash|sh|zsh)\b/.test(code)) {
    result.score += 60;
    result.reasons.push('inline code contains remote code execution pattern');
    result.riskFactors.push('rce_inline_code');
  }
  
  // Check for file system operations (Node.js fs, Python os.path)
  if (/\b(fs\.|writeFile|readFile|unlink|rename|mkdir|chmod|os\.path|os\.remove|os\.rmdir)\b/.test(code)) {
    result.score += 25;
    result.reasons.push('inline code contains file system operations');
    result.riskFactors.push('fs_operations');
  }
  
  // Check for child_process
  if (/\b(child_process|exec|execSync|spawn|spawnSync)\b/.test(code)) {
    result.score += 35;
    result.reasons.push('inline code uses child_process');
    result.riskFactors.push('child_process_usage');
  }
  
  // Check for eval in the inline code (nested eval)
  if (/\beval\s*\(/.test(code)) {
    result.score += 40;
    result.reasons.push('inline code contains nested eval');
    result.riskFactors.push('nested_eval');
  }
  
  // Check for base64 decode
  if (/\b(atob|base64|b64decode)\b/.test(code)) {
    result.score += 30;
    result.reasons.push('inline code contains base64 decoding');
    result.riskFactors.push('obfuscated_code');
  }
  
  // Check for dynamic import/require
  if (/\b(require|import)\s*\(['"]/.test(code)) {
    result.score += 20;
    result.reasons.push('inline code dynamically imports modules');
    result.riskFactors.push('dynamic_import');
  }
  
  return result;
}

const DANGEROUS_FLAGS: Record<string, number> = {
  // Dangerous recursive flags (context-dependent)
  '-r': 15,
  '-R': 15,
  '-rf': 25,
  '-fr': 25,
  
  // Force flags
  '-f': 15,
  '--force': 15,
  '--force-with-lease': 10,
  
  // Dangerous modifiers
  '--no-preserve': 10,
  '--no-preserve-root': 30,
  
  // Common safe flags (explicitly zero)
  '-l': 0,  // long listing
  '-a': 0,  // all files
  '-la': 0, // combined (won't be used after splitting)
  '-al': 0,
  '-h': 0,  // help/human-readable
  '-i': 0,  // interactive
  '-v': 0,  // verbose
  '-n': 0,  // dry-run
  '--help': 0,
  '--version': 0,
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
  const intentWeight = INTENT_WEIGHTS[intent];
  score += intentWeight !== undefined ? intentWeight : 20;
  
  // 2. Dangerous flags (context-aware)
  for (const flag of analysis.flags) {
    const baseScore = DANGEROUS_FLAGS[flag] ?? 0;
    
    // Adjust -r/-R score based on command
    let flagScore = baseScore;
    if ((flag === '-r' || flag === '-R') && baseScore > 0) {
      // Recursive is more dangerous with rm, less with grep/cp
      if (analysis.executable === 'rm') {
        flagScore = baseScore + 10; // rm -r is very dangerous
      } else if (['grep', 'find', 'ls', 'cp', 'mv', 'chown', 'chmod'].includes(analysis.executable || '')) {
        flagScore = Math.floor(baseScore * 0.5); // Less dangerous for these
      }
    }
    
    if (flagScore > 0) {
      score += flagScore;
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
    // Expand variables for analysis
    const expandedPath = path
      .replace(/^\$HOME/, '~')
      .replace(/^\$\{HOME\}/, '~');
    
    // Check for variable references to HOME
    const hasHomeVar = path.includes('$HOME') || path.includes('~');
    
    // System root paths
    if (SYSTEM_PATHS.some(sysPath => expandedPath.startsWith(sysPath + '/') || expandedPath === sysPath)) {
      score += 30;
      reasons.push('targeting system root');
      riskFactors.push('system_path');
    }
    // Home directory (including variable references)
    else if (HOME_INDICATORS.some(indicator => expandedPath.startsWith(indicator)) || hasHomeVar) {
      score += 20;
      reasons.push('targeting home directory');
      riskFactors.push('home_directory');
    }
    // Temp directories (safer)
    else if (path.startsWith('/tmp') || path.startsWith('/var/tmp')) {
      score += 5;
    }
    // Project paths (relative, safer)
    else if (path.startsWith('./') || (!path.startsWith('/') && !hasHomeVar)) {
      score += 10;
    }
  }
  
  // 4. Pipeline detection
  if (analysis.hasPipe) {
    // Check for network-to-execution pattern (curl | bash, wget | sh, etc.)
    const hasNetworkToExec = /\b(curl|wget)\b.*\|.*\b(bash|sh|zsh|node|python|ruby|perl)\b/i.test(analysis.command);
    if (hasNetworkToExec) {
      score += 60;
      reasons.push('network to pipe to execution');
      riskFactors.push('remote_code_execution');
    }
    
    // Check for sudo in pipeline (curl | sudo bash)
    const hasSudoInPipe = /\|.*\bsudo\b/.test(analysis.command);
    if (hasSudoInPipe) {
      score += 30;
      reasons.push('sudo in pipeline');
      riskFactors.push('privilege_escalation');
    }
    
    // Check for data exfiltration pattern (cat .env | curl)
    const hasDataExfil = /\b(cat|tail)\b.*\.(env|ssh|pem|key|secret|credential).*\|.*\b(curl|wget)\b/i.test(analysis.command);
    if (hasDataExfil) {
      score += 60;
      reasons.push('potential data exfiltration via pipe');
      riskFactors.push('data_exfiltration');
    } else if (analysis.executable === 'cat' || analysis.executable === 'tail') {
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
  
  // 6. Interpreter-based code execution detection
  if (analysis.executable && INTERPRETER_COMMANDS.includes(analysis.executable)) {
    // Check for -c, -e flags (inline code execution)
    const hasInlineCode = analysis.flags.some(f => f === '-c' || f === '-e' || f === '-exec');
    if (hasInlineCode) {
      score += 20; // Base score for inline code
      reasons.push('interpreter with inline code');
      riskFactors.push('inline_code_execution');
      
      // Recursively analyze the inline code if extracted
      if (analysis.inlineCode) {
        const inlineAnalysis = analyzeInlineCode(analysis.inlineCode);
        score += inlineAnalysis.score;
        reasons.push(...inlineAnalysis.reasons);
        riskFactors.push(...inlineAnalysis.riskFactors);
      }
    }
  }
  
  // 7. Critical commands
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
  
  // Command chaining analysis (&&, ||, ;)
  if (analysis.flags.includes('chained_command')) {
    // Split command by && ||, and ; to analyze each part
    const commands = analysis.command.split(/&&|\|\||;/).map(c => c.trim()).filter(c => c.length > 0);
    
    // Check if any command in the chain is dangerous
    for (const cmd of commands) {
      // Check for destructive commands in chain
      if (/\b(rm\s+-rf\s+[/~]|dd\s+if=|mkfs|fdisk)\b/.test(cmd)) {
        score += 40;
        reasons.push('chained command contains destructive operation');
        riskFactors.push('destructive_chain');
      }
      // Check for RCE patterns in chain
      if (/\b(curl|wget)\b.*\|.*\b(bash|sh)\b/.test(cmd)) {
        score += 50;
        reasons.push('chained command contains remote code execution');
        riskFactors.push('rce_in_chain');
      }
      // Check for data exfiltration in chain
      if (/\b(cat|tar)\b.*\|.*\b(curl|wget|nc)\b/.test(cmd)) {
        score += 45;
        reasons.push('chained command contains data exfiltration');
        riskFactors.push('exfil_in_chain');
      }
      // Check for sudo in chain
      if (/\bsudo\b/.test(cmd)) {
        score += 20;
        reasons.push('chained command contains sudo');
        riskFactors.push('sudo_in_chain');
      }
    }
  }
  
  // Base64 encoded command execution (common obfuscation)
  if (/\b(base64\s+(-d|--decode)|base64\s+-d).*\|.*\b(bash|sh|zsh)\b/i.test(analysis.command)) {
    score += 70;
    reasons.push('base64 decoded command piped to shell');
    riskFactors.push('obfuscated_code_execution');
  }
  if (/\becho\s+.*\|\s*base64\s+(-d|--decode).*\|.*\b(bash|sh|zsh)\b/i.test(analysis.command)) {
    score += 75;
    reasons.push('echo piped to base64 decode and shell');
    riskFactors.push('obfuscated_code_execution');
  }
  
  // wget alternative patterns
  if (/\bwget\b.*-qO-.*\|.*\b(bash|sh)\b/i.test(analysis.command)) {
    score += 60;
    reasons.push('wget quiet output piped to shell');
    riskFactors.push('remote_code_execution');
  }
  if (/\bwget\b.*(-O|output-document).*&&.*\b(bash|sh)\b/i.test(analysis.command)) {
    score += 55;
    reasons.push('wget download and execute pattern');
    riskFactors.push('remote_code_execution');
  }
  
  // Git force push to protected branches
  if (analysis.executable === 'git') {
    const hasForce = analysis.flags.some(f => f === '--force' || f === '-f');
    const hasPush = analysis.args.includes('push');
    const hasProtectedBranch = analysis.args.some(arg => 
      arg === 'main' || arg === 'master' || arg === 'develop' || arg === 'production'
    );
    
    if (hasForce && hasPush && hasProtectedBranch) {
      score += 40;
      reasons.push('force push to protected branch');
      riskFactors.push('git_history_destruction');
    }
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
      // Check for dangerous targets
      const hasRootTarget = analysis.paths.some(path => path === '/' || path === '/etc' || path === '/usr');
      const hasHomeTarget = analysis.paths.some(path => 
        path.startsWith('~') || path.startsWith('$HOME') || path.includes('$HOME')
      );
      
      if (hasRootTarget) {
        score += 50; // Make it critical when combined with system path bonus
        reasons.push('rm -rf targeting system root');
        riskFactors.push('recursive_delete_critical');
      } else if (hasHomeTarget) {
        score += 50; // Make it critical when combined with home path bonus
        reasons.push('rm -rf targeting home directory');
        riskFactors.push('recursive_delete_critical');
      } else {
        score += 15; // Project-level rm -rf (danger but not critical)
        reasons.push('rm -rf in project directory');
        riskFactors.push('recursive_delete');
      }
    }
  }
  
  // 9. Command substitution analysis
  const cmdSubs = analysis.args.filter(a => a.startsWith('__cmdsub__:'));
  for (const sub of cmdSubs) {
    const innerCommand = sub.slice('__cmdsub__:'.length);
    if (!innerCommand) continue;
    if (/\brm\s+[-]rf\b/i.test(innerCommand)) {
      score += 50; reasons.push('cmdsub contains rm -rf'); riskFactors.push('destructive_substitution');
    }
    if (/\b(curl|wget)\b/.test(innerCommand)) {
      score += 35; reasons.push('cmdsub contains network op'); riskFactors.push('network_substitution');
    }
    if (/\b(dd|mkfs|fdisk|parted)\b/i.test(innerCommand)) {
      score += 50; reasons.push('cmdsub contains critical cmd'); riskFactors.push('critical_substitution');
    }
    if (/\beval\b/.test(innerCommand)) {
      score += 45; reasons.push('cmdsub contains eval'); riskFactors.push('eval_in_substitution');
    }
    if (/\b(sudo|su)\b/.test(innerCommand)) {
      score += 25; reasons.push('cmdsub contains privilege'); riskFactors.push('privilege_in_substitution');
    }
    if (/\b(base64|atob)\s+[-]d\b/i.test(innerCommand)) {
      score += 40; reasons.push('cmdsub contains base64'); riskFactors.push('obfuscated_substitution');
    }
    if (innerCommand.includes('$(')) {
      score += 20; reasons.push('nested cmdsub'); riskFactors.push('nested_substitution');
    }
    if (/\b(curl|wget)\b.*\|.*\b(bash|sh|zsh)\b/i.test(innerCommand)) {
      score += 40; reasons.push('cmdsub contains RCE'); riskFactors.push('rce_in_substitution');
    }
  }
  
  // 10. Variable expansion analysis
  const vars = analysis.flags.filter(f => f.startsWith('uses_var:'));
  for (const v of vars) {
    const varName = v.slice('uses_var:'.length);
    if (!varName) continue;
    if (['HOME','USER','PASSWORD','API_KEY','TOKEN','SECRET','SSH_KEY'].includes(varName)) {
      score += 15; reasons.push(`sensitive variable: $${varName}`); riskFactors.push('sensitive_variable');
    }
    if (['PATH','LD_PRELOAD','LD_LIBRARY_PATH','PYTHONPATH','NODE_PATH'].includes(varName)) {
      score += 20; reasons.push(`env variable: $${varName}`); riskFactors.push('env_variable_modification');
    }
    if (['IFS','BASH_ENV','SHELLOPTS','BASHOPTS'].includes(varName)) {
      score += 25; reasons.push(`shell variable: $${varName}`); riskFactors.push('shell_control_variable');
    }
    if (/\brm\s+[-]rf\b/i.test(analysis.command) && !['HOME','PATH','IFS'].includes(varName)) {
      score += 10; reasons.push('var with destructive cmd'); riskFactors.push('variable_with_destructive');
    }
  }
  
  // 11. Heredoc body analysis
  const heredocs = analysis.args.filter(a => a.startsWith('__heredoc__:'));
  for (const h of heredocs) {
    const body = h.slice('__heredoc__:'.length);
    if (!body) continue;
    if (/\brm\s+[-]rf\b/i.test(body)) {
      score += 45; reasons.push('heredoc has rm -rf'); riskFactors.push('destructive_heredoc');
    }
    if (/\b(curl|wget|bash|sh|zsh)\b.*\|.*\b(bash|sh|zsh)\b/i.test(body)) {
      score += 50; reasons.push('heredoc has RCE'); riskFactors.push('rce_in_heredoc');
    }
    if (/\b(eval|exec)\b/i.test(body)) {
      score += 40; reasons.push('heredoc has eval/exec'); riskFactors.push('eval_in_heredoc');
    }
    if (/\b(base64|atob)\b/i.test(body)) {
      score += 30; reasons.push('heredoc has obfuscation'); riskFactors.push('obfuscated_heredoc');
    }
    if (/\b(sudo|su)\b/.test(body)) {
      score += 20; reasons.push('heredoc has sudo'); riskFactors.push('privilege_in_heredoc');
    }
  }
  
  // 12. Eval with substitution
  if (analysis.executable === 'eval') {
    if (analysis.args.some(a => a.startsWith('__cmdsub__:'))) {
      score += 30; reasons.push('eval with cmdsub'); riskFactors.push('eval_with_substitution');
    }
    if (/\b(curl|wget)\b/.test(analysis.command)) {
      score += 30; reasons.push('eval with network'); riskFactors.push('eval_with_network');
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
