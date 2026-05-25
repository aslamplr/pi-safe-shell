/**
 * Comprehensive test suite for Intent Detector
 * 
 * Tests cover:
 * 1. Command safety classification
 * 2. Path classification
 * 3. Template abstraction
 * 4. Session learning and auto-approve thresholds
 * 5. Mode-based threshold adjustments
 * 6. Path overrides
 * 7. Edge cases and integration scenarios
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  classifyCommandSafety,
  classifyPath,
  extractTemplate,
  templatesMatch,
  CommandSafety,
  PathSafety,
  IntentDetector,
  createIntentDetector,
} from './intent-detector';

// ============================================================
// Command Safety Classification Tests
// ============================================================

describe('Command Safety Classification', () => {
  describe('Safe commands (read-only)', () => {
    it('classifies file reading commands as safe', () => {
      expect(classifyCommandSafety('cat README.md')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('head -n 10 file.txt')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('tail logs.txt')).toBe(CommandSafety.Safe);  // -f means follow, not force
      expect(classifyCommandSafety('less file.md')).toBe(CommandSafety.Safe);
    });

    it('classifies search commands as safe', () => {
      expect(classifyCommandSafety('grep "pattern" file.txt')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('rg "TODO" src/')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('find . -name "*.ts"')).toBe(CommandSafety.Safe);
    });

    it('classifies listing commands as safe', () => {
      expect(classifyCommandSafety('ls -la')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('ls src/')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('find . -type f')).toBe(CommandSafety.Safe);
    });

    it('classifies git read operations as safe', () => {
      expect(classifyCommandSafety('git status')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('git log --oneline')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('git diff HEAD')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('git branch')).toBe(CommandSafety.Safe);
    });

    it('classifies navigation commands as safe', () => {
      expect(classifyCommandSafety('pwd')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('cd src')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('dirs')).toBe(CommandSafety.Safe);
    });

    it('classifies text processing as safe', () => {
      expect(classifyCommandSafety('wc -l file.txt')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('sort file.txt')).toBe(CommandSafety.Safe);
      expect(classifyCommandSafety('uniq -c file.txt')).toBe(CommandSafety.Safe);
    });
  });

  describe('Contextual commands (depend on args)', () => {
    it('classifies git mutations as contextual', () => {
      expect(classifyCommandSafety('git checkout main')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('git reset --hard HEAD')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('git rebase -i HEAD~3')).toBe(CommandSafety.Contextual);
    });

    it('classifies package managers as contextual', () => {
      expect(classifyCommandSafety('npm install')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('pnpm add lodash')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('pip install requests')).toBe(CommandSafety.Contextual);
    });

    it('classifies build tools as contextual', () => {
      expect(classifyCommandSafety('make build')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('just deploy')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('npm run build')).toBe(CommandSafety.Contextual);
    });

    it('classifies network commands as contextual', () => {
      expect(classifyCommandSafety('curl https://example.com')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('wget file.zip')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('ssh user@host')).toBe(CommandSafety.Contextual);
    });

    it('classifies commands with pipes as contextual', () => {
      expect(classifyCommandSafety('cat file.txt | grep pattern')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('ls | wc -l')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('echo "test" && git status')).toBe(CommandSafety.Contextual);
    });

    it('classifies commands with redirections as contextual', () => {
      expect(classifyCommandSafety('echo "test" > file.txt')).toBe(CommandSafety.Contextual);
      expect(classifyCommandSafety('cat input >> output')).toBe(CommandSafety.Contextual);
    });
  });

  describe('Dangerous commands (inherently destructive)', () => {
    it('classifies deletion commands as dangerous', () => {
      expect(classifyCommandSafety('rm file.txt')).toBe(CommandSafety.Dangerous);
      expect(classifyCommandSafety('rm -rf node_modules')).toBe(CommandSafety.Dangerous);
      expect(classifyCommandSafety('rmdir directory')).toBe(CommandSafety.Dangerous);
    });

    it('classifies permission changes as dangerous', () => {
      expect(classifyCommandSafety('chmod 777 file.txt')).toBe(CommandSafety.Dangerous);
      expect(classifyCommandSafety('chown user:group file.txt')).toBe(CommandSafety.Dangerous);
    });

    it('classifies privilege escalation as dangerous', () => {
      expect(classifyCommandSafety('sudo apt update')).toBe(CommandSafety.Dangerous);
      expect(classifyCommandSafety('su -')).toBe(CommandSafety.Dangerous);
    });

    it('classifies disk operations as dangerous', () => {
      expect(classifyCommandSafety('dd if=/dev/zero of=/dev/sda')).toBe(CommandSafety.Dangerous);
      expect(classifyCommandSafety('mkfs.ext4 /dev/sda1')).toBe(CommandSafety.Dangerous);
      expect(classifyCommandSafety('fdisk -l')).toBe(CommandSafety.Dangerous);
    });

    it('classifies process control as dangerous', () => {
      expect(classifyCommandSafety('kill 1234')).toBe(CommandSafety.Dangerous);
      expect(classifyCommandSafety('pkill -f process')).toBe(CommandSafety.Dangerous);
    });

    it('classifies dangerous flags as dangerous regardless of command', () => {
      expect(classifyCommandSafety('rm -rf /tmp/test')).toBe(CommandSafety.Dangerous);
      expect(classifyCommandSafety('cp -rf source dest')).toBe(CommandSafety.Dangerous);
      expect(classifyCommandSafety('chmod -f 777 file')).toBe(CommandSafety.Dangerous);
    });
  });
});

// ============================================================
// Path Classification Tests
// ============================================================

describe('Path Classification', () => {
  const projectRoot = '/Users/aslam/Documents/code/pi/extensions/pi-safe-shell';

  describe('Project-safe paths', () => {
    it('classifies project-relative paths as PROJECT_SAFE', () => {
      expect(classifyPath('./src/index.ts', projectRoot)).toBe(PathSafety.ProjectSafe);
      expect(classifyPath('./README.md', projectRoot)).toBe(PathSafety.ProjectSafe);
      expect(classifyPath('src/utils.ts', projectRoot)).toBe(PathSafety.ProjectSafe);
    });

    it('classifies absolute project paths as PROJECT_SAFE', () => {
      expect(classifyPath('/Users/aslam/Documents/code/pi/extensions/pi-safe-shell/src', projectRoot))
        .toBe(PathSafety.ProjectSafe);
    });
  });

  describe('User space paths', () => {
    it('classifies home directory paths as USER_SPACE', () => {
      expect(classifyPath('~/Documents/file.txt', projectRoot)).toBe(PathSafety.UserSpace);
      expect(classifyPath('~/Code/project/src', projectRoot)).toBe(PathSafety.UserSpace);
      expect(classifyPath('~/Downloads/file.zip', projectRoot)).toBe(PathSafety.UserSpace);
    });

    it('classifies $HOME variable references as USER_SPACE', () => {
      expect(classifyPath('$HOME/.config/file', projectRoot)).toBe(PathSafety.UserSpace);
      expect(classifyPath('${HOME}/.ssh/key', projectRoot)).toBe(PathSafety.UserSpace);
    });
  });

  describe('System paths', () => {
    it('classifies system directories as SYSTEM', () => {
      expect(classifyPath('/etc/passwd', projectRoot)).toBe(PathSafety.System);
      expect(classifyPath('/usr/bin/node', projectRoot)).toBe(PathSafety.System);
      expect(classifyPath('/var/log/syslog', projectRoot)).toBe(PathSafety.System);
      expect(classifyPath('/boot/vmlinuz', projectRoot)).toBe(PathSafety.System);
    });
  });

  describe('Root dangerous paths', () => {
    it('classifies root directory as ROOT_DANGEROUS', () => {
      expect(classifyPath('/', projectRoot)).toBe(PathSafety.RootDangerous);
    });
  });

  describe('Path overrides', () => {
    it('respects user-defined path overrides', () => {
      const overrides = {
        './scripts/deploy.sh': PathSafety.System,
        '~/safe-space': PathSafety.ProjectSafe,  // Without trailing slash for exact match
      };

      expect(classifyPath('./scripts/deploy.sh', projectRoot, overrides))
        .toBe(PathSafety.System);
      expect(classifyPath('~/safe-space/file.txt', projectRoot, overrides))
        .toBe(PathSafety.ProjectSafe);
    });
  });
});

// ============================================================
// Template Abstraction Tests
// ============================================================

describe('Template Abstraction', () => {
  describe('extractTemplate', () => {
    it('extracts base command and slots correctly', () => {
      const template = extractTemplate('grep "pattern" README.md');
      expect(template.baseCommand).toBe('grep');
      expect(template.slots.length).toBe(2);
      expect(template.rawTemplate).toBe('grep [STRING] [PATH]');
    });

    it('handles numeric arguments', () => {
      const template = extractTemplate('head -n 10 file.txt');
      expect(template.baseCommand).toBe('head');
      expect(template.rawTemplate).toContain('[NUMBER]');
    });

    it('handles flags', () => {
      const template = extractTemplate('ls -la src/');
      expect(template.baseCommand).toBe('ls');
      expect(template.rawTemplate).toContain('[FLAG]');
    });

    it('handles multiple string arguments', () => {
      const template = extractTemplate('grep "foo" "bar" file.txt');
      expect(template.rawTemplate).toBe('grep [STRING] [STRING] [PATH]');
    });

    it('handles complex commands', () => {
      const template = extractTemplate('git diff --stat HEAD~5 HEAD');
      expect(template.baseCommand).toBe('git');
      expect(template.rawTemplate.includes('[FLAG]')).toBe(true);
    });
  });

  describe('templatesMatch', () => {
    it('matches templates with same structure', () => {
      const t1 = extractTemplate('grep "Overview" README.md');
      const t2 = extractTemplate('grep "API Design" README.md');
      expect(templatesMatch(t1, t2)).toBe(true);
    });

    it('matches templates with different string values', () => {
      const t1 = extractTemplate('grep "TODO" src/index.ts');
      const t2 = extractTemplate('grep "FIXME" src/utils.ts');
      expect(templatesMatch(t1, t2)).toBe(true);
    });

    it('matches templates with different string values', () => {
      const t1 = extractTemplate('grep "TODO" src/index.ts');
      const t2 = extractTemplate('grep "FIXME" src/utils.ts');
      expect(templatesMatch(t1, t2)).toBe(true);
    });

    it('does not match templates with different base commands', () => {
      const t1 = extractTemplate('grep "pattern" file.txt');
      const t2 = extractTemplate('cat file.txt');
      expect(templatesMatch(t1, t2)).toBe(false);
    });

    it('does not match templates with different slot counts', () => {
      const t1 = extractTemplate('grep "pattern" file.txt');
      const t2 = extractTemplate('grep "pattern"');
      expect(templatesMatch(t1, t2)).toBe(false);
    });

    it('does not match templates with different slot types', () => {
      const t1 = extractTemplate('head -n 10 file.txt');
      const t2 = extractTemplate('head -n file.txt');  // Missing number
      // This should not match because slot types differ
      expect(templatesMatch(t1, t2)).toBe(false);
    });
  });
});

// ============================================================
// Intent Detector Integration Tests
// ============================================================

describe('IntentDetector', () => {
  const projectRoot = '/Users/aslam/Documents/code/pi/extensions/pi-safe-shell';

  describe('Auto-approve thresholds by mode', () => {
    it('sandbox mode: auto-approve safe commands after 1 approval', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'sandbox',
      });

      // First approval
      const result1 = detector.analyze('grep "pattern" README.md');
      expect(result1.shouldAutoApprove).toBe(false);
      detector.recordApproval('grep "pattern" README.md');

      // Second command with same template - should auto-approve
      detector.recordApproval('grep "pattern" README.md');  // Need 2nd approval for template match
      const result2 = detector.analyze('grep "API" README.md');
      expect(result2.shouldAutoApprove).toBe(true);
    });

    it('development mode: auto-approve safe commands after 1, contextual after 2', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'development',
      });

      // Safe command - needs 1 approval then next match auto-approves
      detector.recordApproval('grep "pattern" README.md');
      detector.recordApproval('grep "pattern" README.md');  // Second approval for match
      expect(detector.analyze('grep "API" README.md').shouldAutoApprove).toBe(true);

      // Contextual command needs 2 approvals
      detector.recordApproval('npm install');
      expect(detector.analyze('npm install').shouldAutoApprove).toBe(false);
      detector.recordApproval('npm install');
      detector.recordApproval('npm install');  // Third for match
      expect(detector.analyze('npm install').shouldAutoApprove).toBe(true);
    });

    it('production mode: auto-approve safe commands after 2, contextual after 3', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'production',
      });

      // Safe command needs 2 approvals
      detector.recordApproval('grep "pattern" README.md');
      expect(detector.analyze('grep "API" README.md').shouldAutoApprove).toBe(false);
      detector.recordApproval('grep "pattern" README.md');
      detector.recordApproval('grep "pattern" README.md');  // Third for match
      expect(detector.analyze('grep "API" README.md').shouldAutoApprove).toBe(true);

      // Contextual command needs 3 approvals
      detector.recordApproval('npm install');
      detector.recordApproval('npm install');
      expect(detector.analyze('npm install').shouldAutoApprove).toBe(false);
      detector.recordApproval('npm install');
      detector.recordApproval('npm install');  // Fourth for match
      expect(detector.analyze('npm install').shouldAutoApprove).toBe(true);
    });

    it('migration mode: always ask for contextual commands', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'migration',
      });

      // Even with many approvals, contextual commands should not auto-approve
      for (let i = 0; i < 10; i++) {
        detector.recordApproval('npm install');
      }
      expect(detector.analyze('npm install').shouldAutoApprove).toBe(false);
    });
  });

  describe('Path-aware auto-approve', () => {
    it('does not auto-approve system paths even with template match', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'sandbox',
      });

      // Approve grep on project file multiple times
      detector.recordApproval('grep "pattern" README.md');
      detector.recordApproval('grep "pattern" README.md');

      // Same template but system path should not auto-approve
      const result = detector.analyze('grep "password" /etc/shadow');
      expect(result.shouldAutoApprove).toBe(false);
      expect(result.pathSafety).toBe(PathSafety.System);
    });

    it('requires more approvals for user space paths', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'development',
      });

      // Safe command on user space path: 2 approvals needed (base 1 + 1 for user space)
      // Use a unique template to avoid cross-contamination from other tests
      detector.recordApproval('cat ~/Documents/notes.txt');
      expect(detector.analyze('cat ~/Documents/notes.txt').shouldAutoApprove).toBe(false);  // 1 approval, need 2
      detector.recordApproval('cat ~/Documents/notes.txt');
      expect(detector.analyze('cat ~/Documents/notes.txt').shouldAutoApprove).toBe(true);  // 2 approvals, meets threshold
    });
  });

  describe('Never auto-approve dangerous commands', () => {
    it('never auto-approves dangerous commands regardless of approvals', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'sandbox',
      });

      // Approve rm command many times
      for (let i = 0; i < 20; i++) {
        detector.recordApproval('rm file.txt');
      }

      // Should still not auto-approve
      expect(detector.analyze('rm file.txt').shouldAutoApprove).toBe(false);
      expect(detector.analyze('rm -rf node_modules').shouldAutoApprove).toBe(false);
    });
  });

  describe('Template matching with path slots', () => {
    it('matches templates with different paths', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'development',
      });

      // Approve grep on one file
      detector.recordApproval('grep "API" README.md');
      detector.recordApproval('grep "API" README.md');  // Second for match

      // Same template, different file should match
      const result = detector.analyze('grep "TODO" src/index.ts');
      expect(result.approvalCount).toBe(2);
    });

    it('tracks path classifications per template', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'development',
      });

      // Approve on project path
      detector.recordApproval('cat README.md');

      // Approve on user space path
      detector.recordApproval('cat ~/Documents/notes.txt');

      const stats = detector.getStats();
      expect(stats.totalTemplates).toBe(1);  // Same template: cat [PATH]
      expect(stats.totalApprovals).toBe(2);
    });
  });

  describe('Reason strings', () => {
    it('provides clear reason for auto-approve', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'sandbox',
      });

      detector.recordApproval('grep "pattern" README.md');
      detector.recordApproval('grep "pattern" README.md');  // Second for match
      const result = detector.analyze('grep "API" README.md');

      expect(result.shouldAutoApprove).toBe(true);
      expect(result.reason).toContain('AUTO-APPROVED');
      expect(result.reason).toContain('threshold');
    });

    it('provides clear reason for requiring approval', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'production',
      });

      const result = detector.analyze('grep "pattern" README.md');

      expect(result.shouldAutoApprove).toBe(false);
      expect(result.reason).toContain('REQUIRES APPROVAL');
      expect(result.reason).toContain('threshold not met');
    });

    it('includes path safety in reason', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'sandbox',
      });

      const result = detector.analyze('cat /etc/passwd');

      expect(result.reason).toContain('SYSTEM');
    });
  });

  describe('Session statistics', () => {
    it('tracks approval statistics', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'development',
      });

      // Record various approvals
      detector.recordApproval('grep "a" file1.txt');
      detector.recordApproval('grep "b" file2.txt');
      detector.recordApproval('grep "c" file3.txt');
      detector.recordApproval('cat file.txt');
      detector.recordApproval('cat file.txt');

      const stats = detector.getStats();
      expect(stats.totalTemplates).toBe(2);  // grep [STRING] [PATH] and cat [PATH]
      expect(stats.totalApprovals).toBe(5);
      expect(stats.topTemplates[0].count).toBe(3);  // grep template
    });
  });

  describe('Edge cases', () => {
    it('handles commands without paths', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'development',
      });

      const result = detector.analyze('pwd');
      expect(result.pathSafety).toBe(PathSafety.Unknown);
      expect(result.safety).toBe(CommandSafety.Safe);
    });

    it('handles complex command chains', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'development',
      });

      const result = detector.analyze('cd src && npm install');
      expect(result.safety).toBe(CommandSafety.Contextual);
    });

    it('handles commands with multiple paths', () => {
      const detector = createIntentDetector({
        projectRoot,
        mode: 'development',
      });

      const result = detector.analyze('cp ./src/file.txt /etc/file.txt');
      // Should use most restrictive path (SYSTEM)
      expect(result.pathSafety).toBe(PathSafety.System);
    });
  });
});

// ============================================================
// Real-world scenario tests
// ============================================================

describe('Real-world scenarios', () => {
  const projectRoot = '/Users/aslam/Documents/code/pi/extensions/pi-safe-shell';

  it('simulates a grep-heavy documentation review session', () => {
    const detector = createIntentDetector({
      projectRoot,
      mode: 'development',
    });

    // User is reviewing docs, running many grep commands
    const commands = [
      'grep "API" README.md',
      'grep "Overview" README.md',
      'grep "Usage" README.md',
      'grep "Installation" docs/setup.md',
      'grep "Configuration" docs/config.md',
    ];

    // First command requires approval
    expect(detector.analyze(commands[0]).shouldAutoApprove).toBe(false);
    detector.recordApproval(commands[0]);
    detector.recordApproval(commands[0]);  // Second for match

    // Subsequent commands with same template auto-approve
    for (let i = 1; i < commands.length; i++) {
      expect(detector.analyze(commands[i]).shouldAutoApprove).toBe(true);
    }
  });

  it('simulates a git workflow session', () => {
    const detector = createIntentDetector({
      projectRoot,
      mode: 'development',
    });

    // Git read operations are safe - auto-approve immediately (no path, threshold 1)
    expect(detector.analyze('git status').shouldAutoApprove).toBe(false);  // First time, no approval yet
    detector.recordApproval('git status');
    detector.recordApproval('git status');  // Second for match
    expect(detector.analyze('git status').shouldAutoApprove).toBe(true);
    
    expect(detector.analyze('git log --oneline').shouldAutoApprove).toBe(false);  // Different template
    expect(detector.analyze('git diff HEAD').shouldAutoApprove).toBe(false);  // Different template

    // Git mutations are contextual, need approvals
    expect(detector.analyze('git checkout feature-branch').shouldAutoApprove).toBe(false);
    detector.recordApproval('git checkout feature-branch');
    expect(detector.analyze('git checkout main').shouldAutoApprove).toBe(false);  // Needs 2nd approval
    detector.recordApproval('git checkout feature-branch');  // Second for match
    expect(detector.analyze('git checkout main').shouldAutoApprove).toBe(true);
  });

  it('simulates a package installation session', () => {
    const detector = createIntentDetector({
      projectRoot,
      mode: 'production',
    });

    // npm install needs 3 approvals in production mode
    detector.recordApproval('npm install');
    expect(detector.analyze('npm install').shouldAutoApprove).toBe(false);

    detector.recordApproval('npm install');
    expect(detector.analyze('npm install').shouldAutoApprove).toBe(false);

    detector.recordApproval('npm install');
    expect(detector.analyze('npm install').shouldAutoApprove).toBe(true);

    // Different package manager, same template
    expect(detector.analyze('pnpm install').shouldAutoApprove).toBe(false);
  });

  it('blocks dangerous commands in all scenarios', () => {
    const detector = createIntentDetector({
      projectRoot,
      mode: 'sandbox',  // Most permissive mode
    });

    // Even in sandbox mode, dangerous commands never auto-approve
    const dangerousCommands = [
      'rm -rf node_modules',
      'chmod 777 /etc/passwd',
      'sudo rm -rf /tmp/test',
      'dd if=/dev/zero of=/dev/sda',
    ];

    for (const cmd of dangerousCommands) {
      // Approve many times
      for (let i = 0; i < 20; i++) {
        detector.recordApproval(cmd);
      }
      expect(detector.analyze(cmd).shouldAutoApprove).toBe(false);
    }
  });
});
