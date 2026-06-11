# Metrics Report: proposed

Generated: 2026-06-11T11:16:18.526Z
Corpus size: 210 commands

## Expected Distribution

| Level | Count | % |
|-------|-------|---|
| safe | 147 | 70.0% |
| caution | 27 | 12.9% |
| danger | 10 | 4.8% |
| critical | 26 | 12.4% |

## Aggregate Metrics

| Metric | Value |
|--------|-------|
| **Total commands** | 210 |
| **Average score** | 19.3 |
| **Correct classifications** | 205 / 210 (97.6%) |
| **True Negatives** (correctly allowed) | 144 |
| **True Positives** (correctly flagged) | 61 |
| **False Positives** (over-blocked) | 5 |
| **False Negatives** (under-blocked) | 0 |
| **Recall** (caught dangerous / total dangerous) | 96.8% |
| **False alarm rate** (FP / expected-to-allow) | 3.5% |

## Score Distribution

| Range | Count | Bar |
|-------|-------|-----|
| 0 | 144 | `██████████████████████████████` |
| 1-10 | 0 | `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 11-20 | 0 | `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 21-30 | 28 | `██████░░░░░░░░░░░░░░░░░░░░░░░░` |
| 31-40 | 0 | `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 41-50 | 0 | `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 51-60 | 3 | `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 61-70 | 8 | `██░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 71-80 | 1 | `░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 81-90 | 3 | `█░░░░░░░░░░░░░░░░░░░░░░░░░░░░░` |
| 91-100 | 23 | `█████░░░░░░░░░░░░░░░░░░░░░░░░░` |

**Thresholds**: safe ≤ 20, caution 21-50, danger 51-80, critical ≥ 81

## False Positives by Category

Categories with the most over-blocking. Lower is better.

| Category | Total | FP | FP Rate | FN | FN Rate |
|----------|-------|----|---------|----|---------| 
| edge | 10 | 3 | 30% | 0 | 0% |
| rm | 5 | 2 | 40% | 0 | 0% |
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
| rce | 12 | 0 | 0% | 0 | 0% |
| text | 6 | 0 | 0% | 0 | 0% |
| process | 11 | 0 | 0% | 0 | 0% |

## Worst Offenders

Commands where the prediction was most wrong. FP = over-blocked, FN = under-blocked.

| Result | Score | Expected | Actual | Command |
|--------|-------|----------|--------|---------|
| FP | 70 | caution | danger | `rm -f file` |
| FP | 70 | caution | danger | `rm -v file` |
| FP | 25 | safe | caution | `~` — _just home indicator_ |
| FP | 25 | safe | caution | `VAR=value ls` — _env var prefix_ |
| FP | 25 | safe | caution | `alias ll="ls -la"; ll` — _alias then use_ |
