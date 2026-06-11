/**
 * Metrics Check — CI gate to prevent metrics regressions
 *
 * Runs the corpus against the current implementation and fails if:
 *   - False positives exceed threshold
 *   - False negatives exceed threshold
 *   - Accuracy falls below threshold
 *
 * Usage:
 *   tsx scripts/metrics-check.ts          # Run with default thresholds
 *   tsx scripts/metrics-check.ts --strict  # Tighter thresholds
 *
 * Default thresholds (matches our 0.7.0 release targets):
 *   - FP ≤ 5
 *   - FN = 0
 *   - Accuracy ≥ 97%
 *
 * Strict mode (for releases):
 *   - FP ≤ 3
 *   - FN = 0
 *   - Accuracy ≥ 98%
 */

import {
  initParser,
  analyzeCommand,
} from '../src/ast-analyzer';
import { scoreCommandV2 } from '../src/ast-analyzer-v2';
import { CORPUS, type ExpectedLevel } from './metrics-corpus';

const args = process.argv.slice(2);
const strict = args.includes('--strict');

const THRESHOLDS = {
  default: { fp: 5, fn: 0, accuracy: 0.97 },
  strict: { fp: 3, fn: 0, accuracy: 0.98 },
};

const SEVERITY: Record<ExpectedLevel, number> = {
  safe: 0,
  caution: 1,
  danger: 2,
  critical: 3,
};

function classifyResult(actual: ExpectedLevel, expected: ExpectedLevel): 'TP' | 'TN' | 'FP' | 'FN' {
  if (actual === expected) {
    return SEVERITY[expected] === 0 ? 'TN' : 'TP';
  }
  if (SEVERITY[actual] > SEVERITY[expected]) return 'FP';
  return 'FN';
}

async function main() {
  const t = strict ? THRESHOLDS.strict : THRESHOLDS.default;
  console.log(`Mode: ${strict ? 'strict' : 'default'}`);
  console.log(`Thresholds: FP ≤ ${t.fp}, FN ≤ ${t.fn}, accuracy ≥ ${(t.accuracy * 100).toFixed(0)}%\n`);

  await initParser();

  let fp = 0;
  let fn = 0;
  let correct = 0;
  const failures: Array<{ command: string; expected: string; actual: string; result: string }> = [];

  for (const entry of CORPUS) {
    try {
      const analysis = analyzeCommand(entry.command);
      const risk = scoreCommandV2(analysis);
      const actual = risk.level as ExpectedLevel;
      const result = classifyResult(actual, entry.expected);

      if (result === 'FP') fp++;
      if (result === 'FN') fn++;
      if (result === 'TP' || result === 'TN') correct++;

      if (result === 'FP' || result === 'FN') {
        failures.push({ command: entry.command, expected: entry.expected, actual, result });
      }
    } catch (e) {
      // Treat errors as FN (safer default)
      fn++;
      failures.push({
        command: entry.command,
        expected: entry.expected,
        actual: 'safe',
        result: 'FN',
      });
    }
  }

  const total = CORPUS.length;
  const accuracy = correct / total;
  const passed = fp <= t.fp && fn <= t.fn && accuracy >= t.accuracy;

  console.log('=== Results ===');
  console.log(`Total:     ${total}`);
  console.log(`Correct:   ${correct} (${(accuracy * 100).toFixed(1)}%)`);
  console.log(`FP:        ${fp} ${fp <= t.fp ? '✅' : '❌'} (threshold: ${t.fp})`);
  console.log(`FN:        ${fn} ${fn <= t.fn ? '✅' : '❌'} (threshold: ${t.fn})`);
  console.log(`Accuracy:  ${(accuracy * 100).toFixed(1)}% ${accuracy >= t.accuracy ? '✅' : '❌'} (threshold: ${(t.accuracy * 100).toFixed(0)}%)`);

  if (failures.length > 0) {
    console.log('\n=== Failures ===');
    for (const f of failures) {
      const cmd = f.command.length > 80 ? f.command.substring(0, 80) + '...' : f.command;
      console.log(`[${f.result}] expected=${f.expected} actual=${f.actual}: ${cmd}`);
    }
  }

  console.log('');
  if (passed) {
    console.log('✅ All metrics checks PASSED');
    process.exit(0);
  } else {
    console.log('❌ Metrics check FAILED');
    process.exit(1);
  }
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
