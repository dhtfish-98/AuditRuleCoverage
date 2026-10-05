> 目录已整理：文档在「项目文档」，构建、缓存与暂存输入在「Build」。从仓库根目录运行 `python3 构建.py --build`；如需使用本文原有源码命令，先运行 `python3 构建.py --stage --ci`，再进入 `Build/源码`。暂存会恢复原输入路径。现有版本和历史验证记录按各自提交理解。

# AuditRuleCoverage

Version **0.1.3**.

New implementation author: **dhtfish98**. Copyright (c) 2026 dhtfish98 applies to the new implementation code. Upstream policy data, original notices and source references retain their original attribution.

Audit rule syntax and complete frozen baseline coverage. A complete independent new-scope defensive project; upstream-wide rewriting and equivalence are not claimed.

Input: `{ "rules": "audit rule text", "check_baseline": true }`. Selected syntax checks parse watch permissions/keys, syscall action/list, repeated fields/syscalls, directives, immutable ordering, ABI attribution, typed filter operands, suppressed auditing and error-ignore mode. Numeric operands support complete ASCII decimal/octal/hex forms in explicit 32-bit ranges, rejecting trailing bytes, oversized values and malformed operators. Success is 0/1; exit is signed 32-bit; PID/PPID are nonnegative signed 32-bit; other selected numeric fields use unsigned 32-bit, with signed syscall-argument values allowed down to -2^31. UID unset/-1 is recognized, other portable negative UID representations stay OPEN. Field/list/operator restrictions, 63-field slots, 31-byte keys, arch-before-syscall order and UID/GID inter-field comparisons are checked. Symbolic NSS identities, errno names, SELinux labels, message types, feature-dependent fields and syscall spellings outside the frozen set remain OPEN. No host table is consulted. This is deliberately stricter than permissive/truncating C conversions in auditctl; invalid selected syntax is ERROR, never evidence of actual kernel rejection. All collecting/filter rules from the complete frozen upstream baseline are checked by normalized literal identity including attribution keys. `check_baseline:false` restricts the report to all supplied rule syntax/risk checks and labels that scope. Order, distro identities, paths, ABI availability and kernel loading remain OPEN. Coverage is not semantic equivalence. The upstream baseline contains `-i`; a complete copy therefore correctly reports a failure for masked load errors, even if all baseline identities match. The tool never invokes auditctl, augenrules or systemctl.

## Use

Install the published v0.1.3 wheel from GitHub Releases, or run `python3 构建.py --build` from the repository root and install the wheel under the reported `Build/新构建/.../发行/` directory; then run `audit-rule-coverage examples/good.json`. Or use `python -m audit_rule_coverage examples/good.json`. JSON input is limited to 2 MiB, 32 nesting levels and 100000 nodes; duplicate keys, non-finite values, changed files, symlinks and non-regular files are rejected. Findings are capped at 20000. No network requests, host collection, policy changes or shell execution occur.

## Output and verification

Each finding includes check, PASS/FAIL/OPEN, evidence location and explanation. Overall status is FAIL if a check fails; otherwise OPEN for incomplete/unsupported input; otherwise PASS for only this declared static scope. Exit codes: PASS 0, FAIL 1, ERROR 2, OPEN 3. See `examples/expectations.json`, `tests/`, `VALIDATION.md`, `ORIGIN.md`, `NOTICE` where present, and exact `artifacts/validation.json`.

Snapshot results do not prove runtime security, actual authorization, upstream equivalence or CVP qualification/approval.


The file CLI requires non-following, non-blocking descriptor support (`O_NOFOLLOW` and `O_NONBLOCK`). Missing capabilities return controlled ERROR without weakening safe-file reads. This profile targets capable macOS/Linux environments; native Windows file-CLI behavior has not been verified. Windows observations remain supplied JSON data.

Selected typed field/operator guards follow the frozen Linux `audit_field_valid` matrix: identity and selected numeric fields reject bitwise operators, equality-only fields reject ordering/bitwise operations, and filesystem filters permit only fstype/key. Syscall arguments, personality and devminor retain bitwise support. Root/wildcard watch paths are OPEN; absolute watch paths are limited to 4096 UTF-8 bytes. Existing stricter profile choices (equality-only inode, equality key/perm, host-dependent label/features OPEN) remain explicit and are not claims of full kernel equivalence.

Literal baseline identities preserve the distinction between `-C` inter-field comparisons and `-F` identity-name/numeric filters; substituting one does not establish the frozen comparison rule. Attribution `-k`/`-F key=` remains normalized as the same key declaration.
