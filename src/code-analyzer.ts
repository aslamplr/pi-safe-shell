/**
 * Code-based bypass prevention analyzer for pi-safe-shell
 * 
 * Detects dangerous API calls in generated code (Node.js, Python) to prevent
 * agents from bypassing shell analysis by writing code instead.
 * 
 * Pattern-based detection (deterministic, fast, privacy-preserving):
 * - Regex matching against dangerous API patterns
 * - Context-aware path analysis
 * - Obfuscation detection
 * - Dangerous call chain detection
 */

// ============================================================
// Types
// ============================================================

export type CodeLanguage = 'javascript' | 'python' | 'typescript' | 'unknown';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export type RiskCategory = 
  | 'fs_destructive'      // rm, unlink, rmtree
  | 'shell_exec'          // exec, spawn, system
  | 'network'             // https, requests (exfil risk)
  | 'code_exec'           // eval, exec, Function
  | 'fs_sensitive';       // readFile, open (could read secrets)

export interface DangerousCall {
  api: string;            // e.g., "fs.unlinkSync"
  location: string;       // e.g., "line 5"
  severity: Severity;
  category: RiskCategory;
  argument?: string;      // e.g., "/etc/passwd"
  lineContent?: string;   // Full line of code
}

export interface CodeAnalysis {
  language: CodeLanguage;
  dangerousCalls: DangerousCall[];
  score: number;          // 0-100
  level: 'safe' | 'caution' | 'danger' | 'critical';
  reasons: string[];
  riskFactors: string[];
  obfuscationDetected: boolean;
  obfuscationPatterns: string[];
}

// ============================================================
// Dangerous API Definitions - Node.js
// ============================================================

const NODE_DANGEROUS_APIS: Record<string, { severity: Severity; category: RiskCategory }> = {
  // File System - Destructive (highest risk)
  'fs.rm': { severity: 'critical', category: 'fs_destructive' },
  'fs.rmSync': { severity: 'critical', category: 'fs_destructive' },
  'fs.unlink': { severity: 'high', category: 'fs_destructive' },
  'fs.unlinkSync': { severity: 'high', category: 'fs_destructive' },
  'fs.rmdir': { severity: 'high', category: 'fs_destructive' },
  'fs.rmdirSync': { severity: 'high', category: 'fs_destructive' },
  'fs.truncate': { severity: 'medium', category: 'fs_destructive' },
  'fs.truncateSync': { severity: 'medium', category: 'fs_destructive' },
  'fs.promises.rm': { severity: 'critical', category: 'fs_destructive' },
  'fs.promises.unlink': { severity: 'high', category: 'fs_destructive' },
  'fs.promises.rmdir': { severity: 'high', category: 'fs_destructive' },
  
  // Shell Execution - Complete bypass (critical)
  'child_process.exec': { severity: 'critical', category: 'shell_exec' },
  'child_process.execSync': { severity: 'critical', category: 'shell_exec' },
  'child_process.spawn': { severity: 'high', category: 'shell_exec' },
  'child_process.spawnSync': { severity: 'high', category: 'shell_exec' },
  'child_process.execFile': { severity: 'high', category: 'shell_exec' },
  'child_process.execFileSync': { severity: 'high', category: 'shell_exec' },
  'exec': { severity: 'critical', category: 'shell_exec' },
  'execSync': { severity: 'critical', category: 'shell_exec' },
  'spawn': { severity: 'high', category: 'shell_exec' },
  'spawnSync': { severity: 'high', category: 'shell_exec' },
  
  // Network - Data exfiltration risk
  'https.request': { severity: 'medium', category: 'network' },
  'https.get': { severity: 'medium', category: 'network' },
  'http.request': { severity: 'medium', category: 'network' },
  'http.get': { severity: 'medium', category: 'network' },
  'fetch': { severity: 'medium', category: 'network' },
  'axios.post': { severity: 'high', category: 'network' },
  'axios.put': { severity: 'high', category: 'network' },
  'axios.delete': { severity: 'medium', category: 'network' },
  'requests.post': { severity: 'high', category: 'network' },
  
  // Code Execution - Dynamic code (critical)
  'eval': { severity: 'critical', category: 'code_exec' },
  'Function': { severity: 'high', category: 'code_exec' },
  'vm.runInContext': { severity: 'critical', category: 'code_exec' },
  'vm.runInNewContext': { severity: 'critical', category: 'code_exec' },
  'vm.runThisContext': { severity: 'high', category: 'code_exec' },
  
  // File System - Sensitive (could read secrets)
  'fs.readFile': { severity: 'medium', category: 'fs_sensitive' },
  'fs.readFileSync': { severity: 'medium', category: 'fs_sensitive' },
  'fs.createReadStream': { severity: 'medium', category: 'fs_sensitive' },
  'fs.promises.readFile': { severity: 'medium', category: 'fs_sensitive' },
};

// ============================================================
// Dangerous API Definitions - Python
// ============================================================

const PYTHON_DANGEROUS_APIS: Record<string, { severity: Severity; category: RiskCategory }> = {
  // File System - Destructive
  'shutil.rmtree': { severity: 'critical', category: 'fs_destructive' },
  'os.remove': { severity: 'high', category: 'fs_destructive' },
  'os.unlink': { severity: 'high', category: 'fs_destructive' },
  'os.rmdir': { severity: 'high', category: 'fs_destructive' },
  'os.removedirs': { severity: 'high', category: 'fs_destructive' },
  'os.truncate': { severity: 'medium', category: 'fs_destructive' },
  'pathlib.Path.unlink': { severity: 'high', category: 'fs_destructive' },
  'pathlib.Path.rmdir': { severity: 'high', category: 'fs_destructive' },
  
  // Shell Execution - Complete bypass
  'os.system': { severity: 'critical', category: 'shell_exec' },
  'os.popen': { severity: 'high', category: 'shell_exec' },
  'subprocess.call': { severity: 'high', category: 'shell_exec' },
  'subprocess.run': { severity: 'high', category: 'shell_exec' },
  'subprocess.Popen': { severity: 'high', category: 'shell_exec' },
  'subprocess.check_output': { severity: 'high', category: 'shell_exec' },
  'subprocess.check_call': { severity: 'medium', category: 'shell_exec' },
  'subprocess.getoutput': { severity: 'high', category: 'shell_exec' },
  'subprocess.getstatusoutput': { severity: 'medium', category: 'shell_exec' },
  
  // Network - Data exfiltration
  'requests.post': { severity: 'high', category: 'network' },
  'requests.put': { severity: 'high', category: 'network' },
  'requests.delete': { severity: 'medium', category: 'network' },
  'urllib.request.urlopen': { severity: 'medium', category: 'network' },
  'http.client.HTTPConnection': { severity: 'medium', category: 'network' },
  'socket.connect': { severity: 'medium', category: 'network' },
  
  // Code Execution
  'eval': { severity: 'critical', category: 'code_exec' },
  'exec': { severity: 'critical', category: 'code_exec' },
  'compile': { severity: 'high', category: 'code_exec' },
  '__import__': { severity: 'medium', category: 'code_exec' },
  
  // File System - Sensitive
  'open': { severity: 'low', category: 'fs_sensitive' },
  'os.read': { severity: 'medium', category: 'fs_sensitive' },
  'os.write': { severity: 'medium', category: 'fs_sensitive' },
};

// ============================================================
// Obfuscation Detection Patterns
// ============================================================

const OBFUSCATION_PATTERNS: Record<string, RegExp> = {
  // Base64 decode + execute (Node.js)
  'base64_buffer': /Buffer\.from\([^)]+,\s*['"]base64['"]\)\.toString\(\)/,
  'base64_atob': /\batob\s*\(/,
  
  // Base64 decode (Python/Shell)
  'base64_decode': /base64\s+(-d|--decode)/,
  'base64_b64decode': /\bb64decode\s*\(/,
  
  // Hex/octal escape sequences
  'hex_escape': /\\x[0-9a-fA-F]{2}/,
  'octal_escape': /\\[0-7]{3}/,
  'dollar_hex': /\$'\\x[0-9a-fA-F]+'/,
  
  // String concatenation to hide intent
  'string_concat': /['"][^'"]{10,}['"]\s*\+\s*['"][^'"]+['"]/,
  
  // Dynamic eval with string building
  'eval_concat': /eval\s*\([^)]*\+[^)]*\)/,
  
  // Character code obfuscation
  'from_char_code': /String\.fromCharCode\s*\(/,
  'chr_concat': /\bchr\s*\(\d+\)/,
  
  // Reverse string execution
  'reverse_exec': /\.split\(['"]['"]\)\.reverse\(\)\.join\(['"]['"]\)/,
};

// ============================================================
// Dangerous Call Chains (multi-pattern attacks)
// ============================================================

const DANGEROUS_CHAINS: Array<{ 
  pattern: RegExp; 
  severity: Severity; 
  description: string;
}> = [
  {
    pattern: /fs\.readFileSync\([^)]+\)[\s\S]*?axios\.post/,
    severity: 'critical',
    description: 'File read followed by network POST (data exfiltration)',
  },
  {
    pattern: /fs\.createReadStream[\s\S]*?https\.request/,
    severity: 'critical',
    description: 'File stream to network request (exfiltration)',
  },
  {
    pattern: /child_process\.exec[\s\S]*?rm\s+-rf/,
    severity: 'critical',
    description: 'Shell execution with rm -rf',
  },
  {
    pattern: /shutil\.rmtree[\s\S]*?\/(etc|home|Users)/,
    severity: 'critical',
    description: 'Recursive delete of system/user directory',
  },
  {
    pattern: /os\.system[\s\S]*?rm\s+-rf/,
    severity: 'critical',
    description: 'OS system call with rm -rf',
  },
  {
    pattern: /requests\.post[\s\S]*?readFileSync/,
    severity: 'critical',
    description: 'Network POST with file read (exfiltration)',
  },
];

// ============================================================
// Path Analysis
// ============================================================

const LEGITIMATE_PATH_PATTERNS: RegExp[] = [
  /.*\/(build|dist|out|target|coverage)\/.*$/,
  /.*\/node_modules\/.*$/,
  /.*\/\.next\/.*$/,
  /.*\/\.nuxt\/.*$/,
  /.*\/tmp\/.*$/,
  /.*\/temp\/.*$/,
  /.*\/\.cache\/.*$/,
  /.*\/vendor\/.*$/,
  /^\.\//,  // Relative paths starting with ./
];

const SUSPICIOUS_PATH_PATTERNS: RegExp[] = [
  /\/etc\/.*$/,
  /\/usr\/.*$/,
  /\/bin\/.*$/,
  /\/sbin\/.*$/,
  /\/var\/.*$/,
  /\/boot\/.*$/,
  /\/dev\/.*$/,
  /\/proc\/.*$/,
  /\/sys\/.*$/,
  /\/Users\/[^/]+\/.*$/,
  /\/home\/[^/]+\/.*$/,
  /.*\/\.ssh\/.*$/,
  /.*\/\.(env|bash_profile|bashrc|zshrc)$/,
  /.*\/(secret|credential|password|key|token).*\.(txt|json|yaml|yml)$/,
];

function isLegitimatePath(path: string): boolean {
  return LEGITIMATE_PATH_PATTERNS.some(p => p.test(path));
}

function isSuspiciousPath(path: string): boolean {
  // First check explicit suspicious patterns
  if (SUSPICIOUS_PATH_PATTERNS.some(p => p.test(path))) {
    return true;
  }
  
  // Also check for dangerous single-component paths
  if (path === '/' || path === '/etc' || path === '/usr' || path === '/bin' || path === '/sbin') {
    return true;
  }
  
  // Check if path starts with dangerous prefixes
  if (path.startsWith('/Users/') || path.startsWith('/home/') || path.startsWith('/etc/')) {
    return true;
  }
  
  return false;
}

// ============================================================
// Language Detection
// ============================================================

export function detectLanguage(code: string, filePath?: string): CodeLanguage {
  // Check file extension first
  if (filePath) {
    if (filePath.endsWith('.ts') || filePath.endsWith('.tsx')) return 'typescript';
    if (filePath.endsWith('.js') || filePath.endsWith('.jsx')) return 'javascript';
    if (filePath.endsWith('.py')) return 'python';
  }
  
  // Heuristic detection from code content
  const hasPython = /\b(import|def |class |print\(|if __name__|pip install)\b/.test(code);
  const hasJS = /\b(const|let|var|require\(|function|console\.log|=>)\b/.test(code);
  
  if (hasPython && !hasJS) return 'python';
  if (hasJS && !hasPython) return 'javascript';
  
  return 'unknown';
}

// ============================================================
// Code Analysis
// ============================================================

export function analyzeCode(code: string, filePath?: string): CodeAnalysis {
  const language = detectLanguage(code, filePath);
  const apis = language === 'python' ? PYTHON_DANGEROUS_APIS : 
               language === 'javascript' || language === 'typescript' ? NODE_DANGEROUS_APIS :
               { ...NODE_DANGEROUS_APIS, ...PYTHON_DANGEROUS_APIS };
  
  const dangerousCalls: DangerousCall[] = [];
  const riskFactors: string[] = [];
  const reasons: string[] = [];
  let score = 0;
  
  // Split code into lines for line-by-line analysis
  const lines = code.split('\n');
  
  // 1. Detect dangerous API calls
  for (const [api, config] of Object.entries(apis)) {
    // Escape dots for regex
    const escapedApi = api.replace(/\./g, '\\.');
    const regex = new RegExp(`\\b${escapedApi}\\s*\\(`, 'g');
    
    let match;
    while ((match = regex.exec(code)) !== null) {
      // Find line number
      const beforeMatch = code.slice(0, match.index);
      const lineNum = (beforeMatch.match(/\n/g) || []).length + 1;
      const lineContent = lines[lineNum - 1]?.trim() || '';
      
      // Skip if in comment (simple detection)
      if (lineContent.startsWith('//') || lineContent.startsWith('#')) {
        continue;
      }
      
      // Skip if looks like string literal assignment (heuristic)
      if (/^["'].*["']\s*=/.test(lineContent) || /^const\s+\w+\s*=\s*["']/.test(lineContent)) {
        continue;
      }
      
      // Extract argument (simplified - first parenthesized group)
      const argMatch = code.slice(match.index).match(/\([^)]{0,100}\)/);
      const argument = argMatch ? argMatch[0].slice(1, -1) : undefined;
      
      // Check path context
      let severity = config.severity;
      let pathScoreMultiplier = 1.0;
      
      if (argument && (argument.includes('"') || argument.includes("'"))) {
        const extractedPath = argument.replace(/['"]/g, '');
        if (isLegitimatePath(extractedPath)) {
          // Reduce severity for legitimate paths
          severity = severity === 'critical' ? 'high' : 
                     severity === 'high' ? 'medium' : severity;
          pathScoreMultiplier = 0.5;
        } else if (isSuspiciousPath(extractedPath)) {
          // Increase severity for suspicious paths
          severity = 'critical';
          pathScoreMultiplier = 1.5;
        }
      }
      
      // Also check line content for paths
      if (!argument && isSuspiciousPath(lineContent)) {
        severity = 'critical';
        pathScoreMultiplier = 1.5;
      }
      
      dangerousCalls.push({
        api,
        location: `line ${lineNum}`,
        severity,
        category: config.category,
        argument,
        lineContent,
      });
      
      // Score based on severity with path multiplier
      const baseScore = severity === 'critical' ? 85: 
                       severity === 'high' ? 50 : 
                       severity === 'medium' ? 25 : 10;
      score += Math.round(baseScore * pathScoreMultiplier);
      
      reasons.push(`${api} (${severity}) at line ${lineNum}`);
      if (!riskFactors.includes(config.category)) {
        riskFactors.push(config.category);
      }
    }
  }
  
  // 2. Detect obfuscation patterns
  const obfuscationPatterns: string[] = [];
  for (const [name, pattern] of Object.entries(OBFUSCATION_PATTERNS)) {
    if (pattern.test(code)) {
      obfuscationPatterns.push(name);
      score += 15; // Bonus for obfuscation
      riskFactors.push(`obfuscation_${name}`);
      reasons.push(`obfuscation pattern: ${name}`);
    }
  }
  
  // 3. Detect dangerous call chains
  for (const { pattern, severity, description } of DANGEROUS_CHAINS) {
    if (pattern.test(code)) {
      score += severity === 'critical' ? 40 : 25;
      riskFactors.push('dangerous_chain');
      reasons.push(`dangerous chain: ${description}`);
    }
  }
  
  // 4. Check for shell execution with variables (injection risk)
  const shellExecWithVar = /(exec|execSync|system|popen)\s*\([^)]*\$\{?[A-Za-z_]/;
  if (shellExecWithVar.test(code)) {
    score += 30;
    riskFactors.push('shell_injection_risk');
    reasons.push('shell execution with variable (injection risk)');
  }
  
  // Clamp score to 0-100
  score = Math.min(100, Math.max(0, score));
  
  // Determine risk level
  const level = score <= 20 ? 'safe' : 
                score <= 50 ? 'caution' : 
                score <= 80 ? 'danger' : 'critical';
  
  return {
    language,
    dangerousCalls,
    score,
    level,
    reasons,
    riskFactors,
    obfuscationDetected: obfuscationPatterns.length > 0,
    obfuscationPatterns,
  };
}

// ============================================================
// Formatting Helpers
// ============================================================

export function formatCodeAnalysis(analysis: CodeAnalysis): string {
  if (analysis.dangerousCalls.length === 0) {
    return `✅ No dangerous API calls detected (${analysis.language})`;
  }
  
  const emoji = analysis.level === 'critical' ? '🔒' : 
                analysis.level === 'danger' ? '⚠️' : '⚡';
  
  let output = `${emoji} Code Analysis (${analysis.level.toUpperCase()}: ${analysis.score}/100)\n\n`;
  output += `Language: ${analysis.language}\n\n`;
  
  if (analysis.obfuscationDetected) {
    output += `⚠️ Obfuscation Detected: ${analysis.obfuscationPatterns.join(', ')}\n\n`;
  }
  
  output += `Dangerous API Calls (${analysis.dangerousCalls.length}):\n`;
  for (const call of analysis.dangerousCalls) {
    output += `  • ${call.api} (${call.severity}) at ${call.location}\n`;
    if (call.argument) {
      output += `    Argument: ${call.argument?.slice(0, 50)}${call.argument?.length > 50 ? '...' : ''}\n`;
    }
  }
  
  output += `\nRisk Factors: ${analysis.riskFactors.join(', ')}`;
  
  return output;
}
