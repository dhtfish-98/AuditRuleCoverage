# AuditRuleCoverage

Audit rule syntax and complete frozen baseline coverage. A complete independent new-scope defensive project; upstream-wide rewriting and equivalence are not claimed.

Input: `{ "rules": "audit rule text", "check_baseline": true }`. Selected syntax checks parse watch permissions/keys, syscall action/list, repeated fields/syscalls, directives, immutable ordering, ABI attribution, typed filter operands, suppressed auditing and error-ignore mode. Numeric operands support complete ASCII decimal/octal/hex forms in explicit 32-bit ranges, rejecting trailing bytes, oversized values and malformed operators. Success is 0/1; exit is signed 32-bit; PID/PPID are nonnegative signed 32-bit; other selected numeric fields use unsigned 32-bit, with signed syscall-argument values allowed down to -2^31. UID unset/-1 is recognized, other portable negative UID representations stay OPEN. Field/list/operator restrictions, 63-field slots, 31-byte keys, arch-before-syscall order and UID/GID inter-field comparisons are checked. Symbolic NSS identities, errno names, SELinux labels, message types, feature-dependent fields and syscall spellings outside the frozen set remain OPEN. No host table is consulted. This is deliberately stricter than permissive/truncating C conversions in auditctl; invalid selected syntax is ERROR, never evidence of actual kernel rejection. All collecting/filter rules from the complete frozen upstream baseline are checked by normalized literal identity including attribution keys. `check_baseline:false` restricts the report to all supplied rule syntax/risk checks and labels that scope. Order, distro identities, paths, ABI availability and kernel loading remain OPEN. Coverage is not semantic equivalence. The upstream baseline contains `-i`; a complete copy therefore correctly reports a failure for masked load errors, even if all baseline identities match. The tool never invokes auditctl, augenrules or systemctl.

## Use

Install the wheel in `artifacts/`, then run `audit-rule-coverage examples/good.json`. Or use `python -m audit_rule_coverage examples/good.json`. JSON input is limited to 2 MiB, 32 nesting levels and 100000 nodes; duplicate keys, non-finite values, changed files, symlinks and non-regular files are rejected. Findings are capped at 20000. No network requests, host collection, policy changes or shell execution occur.

## Output and verification

Each finding includes check, PASS/FAIL/OPEN, evidence location and explanation. Overall status is FAIL if a check fails; otherwise OPEN for incomplete/unsupported input; otherwise PASS for only this declared static scope. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. See `examples/expectations.json`, `tests/`, `VALIDATION.md`, `ORIGIN.md`, `NOTICE` where present, and exact `artifacts/validation.json`.

Snapshot results do not prove runtime security, actual authorization, upstream equivalence or CVP qualification/approval.
