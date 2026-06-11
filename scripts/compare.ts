/**
 * Metrics Comparison — Side-by-side report of v1 vs v2
 *
 * Usage:
 *   tsx scripts/compare.ts
 *
 * Reads:
 *   docs/metrics/baseline.json (v1)
 *   docs/metrics/proposed.json (v2)
 *
 * Outputs:
 *   docs/metrics/comparison.md
 */

import * as fs from 'fs';
import * as path from 'path';

interface MetricsFile {
  label: string;
  timestamp: string;
  corpus: { total: number; byCategory: Record<string, number>; byExpected: Record<string, number> };
  metrics: {
    total: number;
    byLevel: Record<string, { count: number; correct: number }>;
    byResult: Record<string, number>;
    byCategory: Record<string, { total: number; fp: number; fn: number; tp: number; tn: number }>;
    scoreDistribution: { range: string; count: number }[];
    avgScore: number;
    worstOffenders: Array<{ entry: { command: string; expected: string; category: string; note?: string }; score: number; level: string; result: string }>;
  };
  results: Array<{ command: string; expected: string; actual: string; score: number; result: string; category: string; note?: string }>;
}

const baselinePath = path.resolve('docs/metrics/baseline.json');
const proposedPath = path.resolve('docs/metrics/proposed.json');

if (!fs.existsSync(baselinePath) || !fs.existsSync(proposedPath)) {
  console.error('Need both baseline.json and proposed.json. Run:');
  console.error('  npm run metrics:json -- --label=baseline --impl=v1 > docs/metrics/baseline.json');
  console.error('  npm run metrics:json -- --label=proposed --impl=v2 > docs/metrics/proposed.json');
  process.exit(1);
}

const v1: MetricsFile = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
const v2: MetricsFile = JSON.parse(fs.readFileSync(proposedPath, 'utf8'));

// ============================================================
// Compute comparison
// ============================================================

const v1Results = new Map(v1.results.map(r => [r.command + '|' + r.category, r]));
const v2Results = new Map(v2.results.map(r => [r.command + '|' + r.category, r]));

const lines: string[] = [];

lines.push('# Metrics Comparison: v1 (Baseline) vs v2 (Proposed)');
lines.push('');
lines.push(`Generated: ${new Date().toISOString()}`);
lines.push(`Corpus: ${v1.corpus.total} commands`);
lines.push('');

// ============================================================
// Aggregate comparison table
// ============================================================
lines.push('## Aggregate Comparison');
lines.push('');
lines.push('| Metric | v1 (Baseline) | v2 (Proposed) | Delta | % Change |');
lines.push('|--------|---------------|---------------|-------|----------|');

const v1m = v1.metrics;
const v2m = v2.metrics;

const rows: [string, number, number, string][] = [
  ['Correct classifications', v1m.byResult.TN + v1m.byResult.TP, v2m.byResult.TN + v2m.byResult.TP, 'count'],
  ['True Negatives (correctly allowed)', v1m.byResult.TN, v2m.byResult.TN, 'count'],
  ['True Positives (correctly flagged)', v1m.byResult.TP, v2m.byResult.TP, 'count'],
  ['False Positives (over-blocked)', v1m.byResult.FP, v2m.byResult.FP, 'invert'],
  ['False Negatives (under-blocked)', v1m.byResult.FN, v2m.byResult.FN, 'invert'],
  ['Average score', v1m.avgScore, v2m.avgScore, 'fp'],
];

for (const [label, a, b, type] of rows) {
  const delta = b - a;
  const pct = a !== 0 ? ((delta / a) * 100).toFixed(1) + '%' : 'n/a';
  let indicator = '';
  if (type === 'invert') {
    indicator = delta < 0 ? ' ✅' : (delta > 0 ? ' ⚠️' : '');
  } else if (type === 'fp' || type === 'count') {
    indicator = delta > 0 ? ' ✅' : (delta < 0 ? ' ⚠️' : '');
  }
  lines.push(`| ${label} | ${a.toFixed(1)} | ${b.toFixed(1)} | ${delta > 0 ? '+' : ''}${delta.toFixed(1)} | ${pct}${indicator} |`);
}

const v1Acc = ((v1m.byResult.TN + v1m.byResult.TP) / v1m.total) * 100;
const v2Acc = ((v2m.byResult.TN + v2m.byResult.TP) / v2m.total) * 100;
const accDelta = v2Acc - v1Acc;
lines.push(`| **Accuracy** | **${v1Acc.toFixed(1)}%** | **${v2Acc.toFixed(1)}%** | **${accDelta > 0 ? '+' : ''}${accDelta.toFixed(1)}%** | ${accDelta > 0 ? '✅' : '⚠️'} |`);

const v1Recall = (v1m.byResult.TP / (v1m.byResult.TP + v1m.byResult.FN)) * 100;
const v2Recall = (v2m.byResult.TP / (v2m.byResult.TP + v2m.byResult.FN)) * 100;
lines.push(`| **Recall** (TP / (TP+FN)) | **${v1Recall.toFixed(1)}%** | **${v2Recall.toFixed(1)}%** | **${(v2Recall - v1Recall).toFixed(1)}%** | ${v2Recall >= v1Recall ? '✅' : '⚠️'} |`);

const v1FA = (v1m.byResult.FP / v1.corpus.byExpected.safe) * 100;
const v2FA = (v2m.byResult.FP / v2.corpus.byExpected.safe) * 100;
lines.push(`| **False alarm rate** (FP / safe) | **${v1FA.toFixed(1)}%** | **${v2FA.toFixed(1)}%** | **${(v2FA - v1FA).toFixed(1)}%** | ${v2FA < v1FA ? '✅' : '⚠️'} |`);

lines.push('');

// ============================================================
// Score distribution comparison
// ============================================================
lines.push('## Score Distribution Comparison');
lines.push('');
lines.push('| Range | v1 Count | v2 Count | Delta |');
lines.push('|-------|----------|----------|-------|');
for (const bucket of v1m.scoreDistribution) {
  const v1c = bucket.count;
  const v2c = v2m.scoreDistribution.find(b => b.range === bucket.range)?.count || 0;
  const delta = v2c - v1c;
  const sign = delta > 0 ? '+' : '';
  lines.push(`| ${bucket.range} | ${v1c} | ${v2c} | ${sign}${delta} |`);
}
lines.push('');

// ============================================================
// Per-category comparison
// ============================================================
lines.push('## Per-Category Comparison');
lines.push('');
lines.push('| Category | v1 FP | v2 FP | Δ FP | v1 FN | v2 FN | Δ FN |');
lines.push('|----------|-------|-------|------|-------|-------|------|');

const allCategories = new Set([...Object.keys(v1m.byCategory), ...Object.keys(v2m.byCategory)]);
const catRows: Array<[string, number, number, number, number, number, number]> = [];
for (const cat of allCategories) {
  const v1c = v1m.byCategory[cat] || { fp: 0, fn: 0, tp: 0, tn: 0, total: 0 };
  const v2c = v2m.byCategory[cat] || { fp: 0, fn: 0, tp: 0, tn: 0, total: 0 };
  catRows.push([cat, v1c.fp, v2c.fp, v2c.fp - v1c.fp, v1c.fn, v2c.fn, v2c.fn - v1c.fn]);
}
// Sort by total improvement (FP reduction + FN reduction)
catRows.sort((a, b) => {
  const impA = (a[1] - a[2]) + (a[4] - a[5]);  // FP reduction + FN reduction
  const impB = (b[1] - b[2]) + (b[4] - b[5]);
  return impB - impA;
});

for (const [cat, v1fp, v2fp, dfp, v1fn, v2fn, dfn] of catRows) {
  const fpIndicator = dfp < 0 ? ' ✅' : (dfp > 0 ? ' ⚠️' : '');
  const fnIndicator = dfn > 0 ? ' ⚠️' : (dfn < 0 ? ' ✅' : '');
  lines.push(`| ${cat} | ${v1fp} | ${v2fp} | ${dfp > 0 ? '+' : ''}${dfp}${fpIndicator} | ${v1fn} | ${v2fn} | ${dfn > 0 ? '+' : ''}${dfn}${fnIndicator} |`);
}
lines.push('');

// ============================================================
// Regressions (v2 worse than v1)
// ============================================================
lines.push('## Regressions: Commands v2 Got Wrong That v1 Got Right');
lines.push('');
const regressions: Array<{ command: string; expected: string; v1: string; v2: string; category: string }> = [];
for (const [key, v1r] of v1Results) {
  const v2r = v2Results.get(key);
  if (!v2r) continue;
  if (v1r.result === 'TN' || v1r.result === 'TP') {
    if (v2r.result === 'FP' || v2r.result === 'FN') {
      regressions.push({
        command: v1r.command,
        expected: v1r.expected,
        v1: v1r.actual,
        v2: v2r.actual,
        category: v1r.category,
      });
    }
  }
}
if (regressions.length === 0) {
  lines.push('✅ None — v2 has no regressions vs v1');
} else {
  lines.push(`Found ${regressions.length} regression(s):`);
  lines.push('');
  lines.push('| Category | Expected | v1 → v2 | Command |');
  lines.push('|----------|----------|--------|---------|');
  for (const r of regressions) {
    const cmd = r.command.length > 80 ? r.command.substring(0, 80) + '...' : r.command;
    const safe = cmd.replace(/\|/g, '\\|');
    lines.push(`| ${r.category} | ${r.expected} | ${r.v1} → ${r.v2} | \`${safe}\` |`);
  }
}
lines.push('');

// ============================================================
// Improvements (v2 better than v1)
// ============================================================
lines.push('## Improvements: Commands v2 Fixed');
lines.push('');
const improvements: Array<{ command: string; expected: string; v1: string; v2: string; category: string }> = [];
for (const [key, v2r] of v2Results) {
  const v1r = v1Results.get(key);
  if (!v1r) continue;
  if (v2r.result === 'TN' || v2r.result === 'TP') {
    if (v1r.result === 'FP' || v1r.result === 'FN') {
      improvements.push({
        command: v2r.command,
        expected: v2r.expected,
        v1: v1r.actual,
        v2: v2r.actual,
        category: v2r.category,
      });
    }
  }
}
lines.push(`Found ${improvements.length} improvement(s):`);
lines.push('');
lines.push('| Category | Expected | v1 → v2 | Command |');
lines.push('|----------|----------|--------|---------|');
for (const r of improvements.slice(0, 50)) {  // cap at 50
  const cmd = r.command.length > 80 ? r.command.substring(0, 80) + '...' : r.command;
  const safe = cmd.replace(/\|/g, '\\|');
  lines.push(`| ${r.category} | ${r.expected} | ${r.v1} → ${r.v2} | \`${safe}\` |`);
}
if (improvements.length > 50) {
  lines.push(`| ... | ... | ... | _+${improvements.length - 50} more_ |`);
}
lines.push('');

// ============================================================
// Verdict
// ============================================================
lines.push('## Verdict');
lines.push('');
const verdict: string[] = [];
if (v2m.byResult.FP < v1m.byResult.FP) {
  const fpReduction = ((v1m.byResult.FP - v2m.byResult.FP) / v1m.byResult.FP) * 100;
  verdict.push(`✅ **FP reduced by ${fpReduction.toFixed(0)}%** (${v1m.byResult.FP} → ${v2m.byResult.FP})`);
} else {
  verdict.push(`⚠️ FP did not decrease (${v1m.byResult.FP} → ${v2m.byResult.FP})`);
}

if (v2m.byResult.FN <= v1m.byResult.FN) {
  verdict.push(`✅ **FN did not increase** (${v1m.byResult.FN} → ${v2m.byResult.FN})`);
} else {
  const fnIncrease = v2m.byResult.FN - v1m.byResult.FN;
  verdict.push(`⚠️ FN increased by ${fnIncrease} (${v1m.byResult.FN} → ${v2m.byResult.FN})`);
}

if (regressions.length === 0) {
  verdict.push('✅ **No regressions** — v2 did not break any command v1 got right');
} else {
  verdict.push(`⚠️ ${regressions.length} regression(s) — review the list above`);
}

if (v2Acc >= 90) {
  verdict.push(`✅ **Accuracy ${v2Acc.toFixed(1)}%** — exceeds 90% target`);
} else {
  verdict.push(`⚠️ Accuracy ${v2Acc.toFixed(1)}% — below 90% target`);
}

for (const v of verdict) lines.push(v);
lines.push('');

const out = lines.join('\n');
fs.writeFileSync('docs/metrics/comparison.md', out);
console.log(out);
console.error('\nWritten to docs/metrics/comparison.md');
