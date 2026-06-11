# Metrics Report: proposed

Generated: 2026-06-11T12:43:15.961Z
Corpus size: 213 commands

## Expected Distribution

| Level | Count | % |
|-------|-------|---|
| safe | 145 | 68.1% |
| caution | 27 | 12.7% |
| danger | 12 | 5.6% |
| critical | 29 | 13.6% |

## Aggregate Metrics

| Metric | Value |
|--------|-------|
| **Total commands** | 213 |
| **Average score** | 20.3 |
| **Correct classifications** | 213 / 213 (100.0%) |
| **True Negatives** (correctly allowed) | 145 |
| **True Positives** (correctly flagged) | 68 |
| **False Positives** (over-blocked) | 0 |
| **False Negatives** (under-blocked) | 0 |
| **Recall** (caught dangerous / total dangerous) | 100.0% |
| **False alarm rate** (FP / expected-to-allow) | 0.0% |

## Score Distribution

| Range | Count | Bar |
|-------|-------|-----|
| 0 | 145 | `██████████████████████████████` |
| 1-10 | 0 | `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 11-20 | 0 | `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 21-30 | 27 | `██████░░░░░░░░░░░░░░░░░░░░░░░░` |
| 31-40 | 0 | `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 41-50 | 0 | `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 51-60 | 3 | `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 61-70 | 8 | `██░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 71-80 | 1 | `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 81-90 | 4 | `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 91-100 | 25 | `█████░░░░░░░░░░░░░░░░░░░░░░░░░` |

**Thresholds**: safe ≤ 20, caution 21-50, danger 51-80, critical ≥ 81

## False Positives by Category

Categories with the most over-blocking. Lower is better.

| Category | Total | FP | FP Rate | FN | FN Rate |
|----------|-------|----|---------|----|---------| 
| read-only | 25 | 0 | 0% | 0 | 0% |
| read-flagged | 12 | 0 | 0% | 0 | 0% |
| write | 9 | 0 | 0% | 0 | 0% |
| destructive | 13 | 0 | 0% | 0 | 0% |
| path-variants | 11 | 0 | 0% | 0 | 0% |
| chained | 8 | 0 | 0% | 0 | 0% |
| piped | 8 | 0 | 0% | 0 | 0% |
| inline-code | 5 | 0 | 0% | 0 | 0% |
| redirects | 7 | 0 | 0% | 0 | 0% |
| session-real | 21 | 0 | 0% | 0 | 0% |
| git | 16 | 0 | 0% | 0 | 0% |
| package | 7 | 0 | 0% | 0 | 0% |
| search | 8 | 0 | 0% | 0 | 0% |
| ls | 7 | 0 | 0% | 0 | 0% |
| tail | 4 | 0 | 0% | 0 | 0% |
| cp | 3 | 0 | 0% | 0 | 0% |
| mv | 2 | 0 | 0% | 0 | 0% |
| rm | 5 | 0 | 0% | 0 | 0% |
| rce | 15 | 0 | 0% | 0 | 0% |
| edge | 10 | 0 | 0% | 0 | 0% |
| text | 6 | 0 | 0% | 0 | 0% |
| process | 11 | 0 | 0% | 0 | 0% |

## Worst Offenders

Commands where the prediction was most wrong. FP = over-blocked, FN = under-blocked.

| Result | Score | Expected | Actual | Command |
|--------|-------|----------|--------|---------|
