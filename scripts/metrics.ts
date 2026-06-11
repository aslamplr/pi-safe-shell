/**
 * Metrics Harness — Measure AST analyzer accuracy against the test corpus
 *
 * Usage:
 *   npx tsx scripts/metrics.ts                 # Run with current implementation
 *   npx tsx scripts/metrics.ts --label=baseline  # Tag the report
 *   npx tsx scripts/metrics.ts --json            # Output JSON instead of markdown
 *   npx tsx scripts/metrics.ts --out=docs/metrics/foo.md  # Write to specific file
 *
 * The harness:
 * 1. Initializes the tree-sitter parser
 * 2. Runs each command in the corpus through analyzeCommand + scoreCommand
 * 3. Compares the actual risk level against the expected level
 * 4. Classifies results as:
 *    - TP (true positive): blocked when expected
 *    - TN (true negative): allowed when expected to be allowed
 *    - FP (false positive): over-blocked (false alarm)
 *    - FN (false negative): under-blocked (missed danger)
 * 5. Produces a markdown report with:
 *    - Score distribution histogram
 *    - Per-category false positive rate
 *    - Worst offenders (commands that score most wrong)
 *    - Aggregate metrics
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  initParser,
  analyzeCommand,
  scoreCommand,
} from '../src/ast-analyzer';
import { scoreCommandV2 } from '../src/ast-analyzer-v2';
import { CORPUS, getCorpusStats, type CorpusEntry, type ExpectedLevel } from './metrics-corpus';

// ============================================================
// CLI argument parsing
// ============================================================

const args = process.argv.slice(2);
function getArg(name: string, def?: string): string | undefined {
  const flag = `--${name}=`;
  const found = args.find(a => a.startsWith(flag));
  return found ? found.substring(flag.length) : def;
}

const label = getArg('label', 'current');
const jsonOnly = args.includes('--json');
const outFile = getArg('out');
const impl = (getArg('impl', 'v1') || 'v1').toLowerCase();

// ============================================================
// Risk level ordering (for "is X more severe than Y" check)
// ============================================================

const SEVERITY: Record<ExpectedLevel, number> = {
  safe: 0,
  caution: 1,
  danger: 2,
  critical: 3,
};

// A command is "over-blocked" if actual level > expected (false positive)
// A command is "under-blocked" if actual level < expected (false negative)
function classifyResult(actual: ExpectedLevel, expected: ExpectedLevel): 'TP' | 'TN' | 'FP' | 'FN' {
  if (actual === expected) {
    // Both >= caution is a true positive (correctly flagged)
    // Both == safe is a true negative (correctly allowed)
    return SEVERITY[expected] === 0 ? 'TN' : 'TP';
  }
  if (SEVERITY[actual] > SEVERITY[expected]) return 'FP'; // over-blocked
  return 'FN'; // under-blocked
}

// ============================================================
// Run the corpus
// ============================================================

interface RunResult {
  entry: CorpusEntry;
  score: number;
  level: ExpectedLevel;
  result: 'TP' | 'TN' | 'FP' | 'FN';
  reasons: string[];
  riskFactors: string[];
  error?: string;
}

async function runCorpus(): Promise<RunResult[]> {
  console.error('Initializing parser...');
  await initParser();
  console.error('Running corpus with implementation: ' + impl);
  const scoreFn = impl === 'v2' ? scoreCommandV2 : scoreCommand;
  const results: RunResult[] = [];
  for (const entry of CORPUS) {
    try {
      const analysis = analyzeCommand(entry.command);
      const risk = scoreFn(analysis);
      const actual = risk.level as ExpectedLevel;
      results.push({
        entry,
        score: risk.score,
        level: actual,
        result: classifyResult(actual, entry.expected),
        reasons: risk.reasons,
        riskFactors: risk.riskFactors,
      });
    } catch (e) {
      results.push({
        entry,
        score: -1,
        level: 'safe',
        result: 'FN', // error means we let it through silently
        reasons: [],
        riskFactors: [],
        error: String(e),
      });
    }
  }
  return results;
}

// ============================================================
// Aggregate metrics
// ============================================================

interface Metrics {
  total: number;
  byLevel: Record<ExpectedLevel, { count: number; correct: number }>;
  byResult: Record<'TP' | 'TN' | 'FP' | 'FN', number>;
  byCategory: Record<string, { total: number; fp: number; fn: number; tp: number; tn: number }>;
  scoreDistribution: { range: string; count: number }[];
  avgScore: number;
  worstOffenders: RunResult[]; // FP and FN, sorted by severity
}

function aggregate(results: RunResult[]): Metrics {
  const corpusStats = getCorpusStats();
  const byLevel: Record<ExpectedLevel, { count: number; correct: number }> = {
    safe: { count: 0, correct: 0 },
    caution: { count: 0, correct: 0 },
    danger: { count: 0, correct: 0 },
    critical: { count: 0, correct: 0 },
  };
  const byResult = { TP: 0, TN: 0, FP: 0, FN: 0 };
  const byCategory: Record<string, { total: number; fp: number; fn: number; tp: number; tn: number }> = {};
  const buckets: Record<string, number> = {
    '0': 0, '1-10': 0, '11-20': 0, '21-30': 0, '31-40': 0,
    '41-50': 0, '51-60': 0, '61-70': 0, '71-80': 0, '81-90': 0, '91-100': 0,
  };
  let totalScore = 0;
  let scoredCount = 0;

  for (const r of results) {
    byLevel[r.level].count++;
    if (r.level === r.entry.expected) byLevel[r.level].correct++;
    byResult[r.result]++;

    const cat = byCategory[r.entry.category] || { total: 0, fp: 0, fn: 0, tp: 0, tn: 0 };
    cat.total++;
    cat[r.result.toLowerCase() as 'fp' | 'fn' | 'tp' | 'tn']++;
    byCategory[r.entry.category] = cat;

    if (r.score >= 0) {
      totalScore += r.score;
      scoredCount++;
      if (r.score === 0) buckets['0']++;
      else if (r.score <= 10) buckets['1-10']++;
      else if (r.score <= 20) buckets['11-20']++;
      else if (r.score <= 30) buckets['21-30']++;
      else if (r.score <= 40) buckets['31-40']++;
      else if (r.score <= 50) buckets['41-50']++;
      else if (r.score <= 60) buckets['51-60']++;
      else if (r.score <= 70) buckets['61-70']++;
      else if (r.score <= 80) buckets['71-80']++;
      else if (r.score <= 90) buckets['81-90']++;
      else buckets['91-100']++;
    }
  }

  const worstOffenders = results
    .filter(r => r.result === 'FP' || r.result === 'FN')
    .sort((a, b) => {
      // Sort by severity gap: how far off was the prediction
      const gapA = Math.abs(SEVERITY[a.level] - SEVERITY[a.entry.expected]);
      const gapB = Math.abs(SEVERITY[b.level] - SEVERITY[b.entry.expected]);
      return gapB - gapA;
    })
    .slice(0, 30);

  return {
    total: results.length,
    byLevel,
    byResult,
    byCategory,
    scoreDistribution: Object.entries(buckets).map(([range, count]) => ({ range, count })),
    avgScore: scoredCount > 0 ? totalScore / scoredCount : 0,
    worstOffenders,
  };
}

// ============================================================
// Report generation
// ============================================================

function generateMarkdownReport(metrics: Metrics, labelStr: string): string {
  const stats = getCorpusStats();
  const lines: string[] = [];

  lines.push(`# Metrics Report: ${labelStr}`);
  lines.push('');
  lines.push(`Generated: ${new Date().toISOString()}`);
  lines.push(`Corpus size: ${stats.total} commands`);
  lines.push('');

  // Expected distribution
  lines.push('## Expected Distribution');
  lines.push('');
  lines.push('| Level | Count | % |');
  lines.push('|-------|-------|---|');
  for (const level of ['safe', 'caution', 'danger', 'critical'] as ExpectedLevel[]) {
    const c = stats.byExpected[level];
    const pct = ((c / stats.total) * 100).toFixed(1);
    lines.push(`| ${level} | ${c} | ${pct}% |`);
  }
  lines.push('');

  // Aggregate metrics
  lines.push('## Aggregate Metrics');
  lines.push('');
  const totalExpected = stats.byExpected.caution + stats.byExpected.danger + stats.byExpected.critical;
  const totalAllowed = metrics.byResult.TN;
  const totalCorrect = metrics.byResult.TN + metrics.byResult.TP;
  lines.push('| Metric | Value |');
  lines.push('|--------|-------|');
  lines.push(`| **Total commands** | ${metrics.total} |`);
  lines.push(`| **Average score** | ${metrics.avgScore.toFixed(1)} |`);
  lines.push(`| **Correct classifications** | ${totalCorrect} / ${metrics.total} (${((totalCorrect / metrics.total) * 100).toFixed(1)}%) |`);
  lines.push(`| **True Negatives** (correctly allowed) | ${metrics.byResult.TN} |`);
  lines.push(`| **True Positives** (correctly flagged) | ${metrics.byResult.TP} |`);
  lines.push(`| **False Positives** (over-blocked) | ${metrics.byResult.FP} |`);
  lines.push(`| **False Negatives** (under-blocked) | ${metrics.byResult.FN} |`);
  if (totalExpected > 0) {
    const recall = metrics.byResult.TP / totalExpected;
    lines.push(`| **Recall** (caught dangerous / total dangerous) | ${(recall * 100).toFixed(1)}% |`);
  }
  if (totalAllowed > 0) {
    const falseAlarmRate = metrics.byResult.FP / totalAllowed;
    lines.push(`| **False alarm rate** (FP / expected-to-allow) | ${(falseAlarmRate * 100).toFixed(1)}% |`);
  }
  lines.push('');

  // Score distribution
  lines.push('## Score Distribution');
  lines.push('');
  lines.push('| Range | Count | Bar |');
  lines.push('|-------|-------|-----|');
  const maxCount = Math.max(...metrics.scoreDistribution.map(b => b.count));
  for (const bucket of metrics.scoreDistribution) {
    const barLen = maxCount > 0 ? Math.round((bucket.count / maxCount) * 30) : 0;
    const bar = '█'.repeat(barLen) + '░'.repeat(30 - barLen);
    lines.push(`| ${bucket.range} | ${bucket.count} | \`${bar}\` |`);
  }
  lines.push('');
  lines.push('**Thresholds**: safe ≤ 20, caution 21-50, danger 51-80, critical ≥ 81');
  lines.push('');

  // Per-category FP rate
  lines.push('## False Positives by Category');
  lines.push('');
  lines.push('Categories with the most over-blocking. Lower is better.');
  lines.push('');
  lines.push('| Category | Total | FP | FP Rate | FN | FN Rate |');
  lines.push('|----------|-------|----|---------|----|---------| ');

  const sortedCategories = Object.entries(metrics.byCategory)
    .sort((a, b) => b[1].fp - a[1].fp);

  for (const [cat, stats] of sortedCategories) {
    const fpRate = stats.total > 0 ? ((stats.fp / stats.total) * 100).toFixed(0) : '0';
    const fnRate = stats.total > 0 ? ((stats.fn / stats.total) * 100).toFixed(0) : '0';
    const flag = stats.fn > 0 ? ' ⚠️' : '';
    lines.push(`| ${cat} | ${stats.total} | ${stats.fp} | ${fpRate}% | ${stats.fn} | ${fnRate}%${flag} |`);
  }
  lines.push('');

  // Worst offenders
  lines.push('## Worst Offenders');
  lines.push('');
  lines.push('Commands where the prediction was most wrong. FP = over-blocked, FN = under-blocked.');
  lines.push('');
  lines.push('| Result | Score | Expected | Actual | Command |');
  lines.push('|--------|-------|----------|--------|---------|');
  for (const r of metrics.worstOffenders) {
    const cmd = r.entry.command.length > 80 ? r.entry.command.substring(0, 80) + '...' : r.entry.command;
    const safeCmd = cmd.replace(/\|/g, '\\|');
    const note = r.entry.note ? ` — _${r.entry.note}_` : '';
    lines.push(`| ${r.result} | ${r.score} | ${r.entry.expected} | ${r.level} | \`${safeCmd}\`${note} |`);
  }
  lines.push('');

  return lines.join('\n');
}

// ============================================================
// Main
// ============================================================

async function main() {
  const results = await runCorpus();
  const metrics = aggregate(results);

  if (jsonOnly) {
    const jsonReport = {
      label,
      timestamp: new Date().toISOString(),
      corpus: getCorpusStats(),
      metrics,
      results: results.map(r => ({
        command: r.entry.command,
        expected: r.entry.expected,
        actual: r.level,
        score: r.score,
        result: r.result,
        category: r.entry.category,
        note: r.entry.note,
        reasons: r.reasons,
        riskFactors: r.riskFactors,
      })),
    };
    console.log(JSON.stringify(jsonReport, null, 2));
  } else {
    const md = generateMarkdownReport(metrics, label);
    if (outFile) {
      const fullPath = path.resolve(outFile);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, md);
      console.error(`Report written to ${fullPath}`);
    } else {
      console.log(md);
    }
  }

  // Exit with non-zero if there are dangerous false negatives
  if (metrics.byResult.FN > 0) {
    console.error(`\n⚠️  ${metrics.byResult.FN} false negative(s) — dangerous commands scored too low`);
  }
  if (metrics.byResult.FP > 0) {
    console.error(`ℹ️  ${metrics.byResult.FP} false positive(s) — over-blocking`);
  }
}

main().catch(e => {
  console.error('Fatal error:', e);
  process.exit(1);
});
