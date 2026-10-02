# Origin and boundaries

New implementation author: **dhtfish98**. Copyright (c) 2026 dhtfish98 applies to the new implementation code. Upstream policy data, original notices and source references retain their original attribution.

This is an independent, source-informed, complete **new-scope** defensive tool. It is not a claim to rewrite all of the upstream project or to be behaviorally equivalent to it. Offline configuration evidence does not prove effective runtime protection, authorization, CVP eligibility, or approval.

Upstream references are frozen below. Only policy data explicitly named in NOTICE is bundled; other upstream implementation code and documentation are not copied into the wheel. Source license labels describe references; the new implementation license is Apache-2.0.

- `LICENSE` at `6111069472c26c4120002933b67cef9855dfbad5`, SHA-256 `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`: https://raw.githubusercontent.com/Neo23x0/auditd/6111069472c26c4120002933b67cef9855dfbad5/LICENSE
- `README.md` at `6111069472c26c4120002933b67cef9855dfbad5`, SHA-256 `17dc943a6a1f67bb459a1fc5e24b4764ff93838832a199a3fd188388444684f3`: https://raw.githubusercontent.com/Neo23x0/auditd/6111069472c26c4120002933b67cef9855dfbad5/README.md
- `audit.rules` at `6111069472c26c4120002933b67cef9855dfbad5`, SHA-256 `922b43e7b7c4ce386749a0e63c3a228a13854277de2ef092eddb536a8fa4142e`: https://raw.githubusercontent.com/Neo23x0/auditd/6111069472c26c4120002933b67cef9855dfbad5/audit.rules
- `scripts/lint-rules.sh` at `6111069472c26c4120002933b67cef9855dfbad5`, SHA-256 `d8dcd7e00816f103c697e4059a2bf68fdd48e2e20de8aba90b9f6ecfb1a6f68c`: https://raw.githubusercontent.com/Neo23x0/auditd/6111069472c26c4120002933b67cef9855dfbad5/scripts/lint-rules.sh
- `scripts/validate-rules-ci.sh` at `6111069472c26c4120002933b67cef9855dfbad5`, SHA-256 `c9b06d1b69c9d4c45f53b33430c1e017de80bae34599606d6d64ba009f2b95ef`: https://raw.githubusercontent.com/Neo23x0/auditd/6111069472c26c4120002933b67cef9855dfbad5/scripts/validate-rules-ci.sh
- `.github/workflows/test-rules.yml` at `6111069472c26c4120002933b67cef9855dfbad5`, SHA-256 `59b2fc643f2e3d922f592a53d1fdc50ab169955f5bfc81fa30bb67068ec5623d`: https://raw.githubusercontent.com/Neo23x0/auditd/6111069472c26c4120002933b67cef9855dfbad5/.github/workflows/test-rules.yml

Additional primary syntax references (read as evidence only; no implementation code/documentation is bundled from these references): linux-audit/audit-userspace at `ccd29d145591aba9dd5a01b3207d3dbd18e2413b`. Library files retain their LGPL-2.1-or-later source headers; repository COPYING is GPL-2.0. The new independent code remains Apache-2.0.

- `COPYING`, SHA-256 `32b1062f7da84967e7019d01ab805935caa7ab7321a7ced0e30ebe75e5df1670`: https://raw.githubusercontent.com/linux-audit/audit-userspace/ccd29d145591aba9dd5a01b3207d3dbd18e2413b/COPYING
- `docs/auditctl.8`, SHA-256 `24c4ca2f15182bea236977f10ca7cf172af26a83590a16d6dd8cce5b8490e190`: https://raw.githubusercontent.com/linux-audit/audit-userspace/ccd29d145591aba9dd5a01b3207d3dbd18e2413b/docs/auditctl.8
- `lib/actiontab.h`, SHA-256 `ec951ebb617bb2ab9d7bb72696b7f4720838431a0b8fa5b7cd76b824ad2f326c`: https://raw.githubusercontent.com/linux-audit/audit-userspace/ccd29d145591aba9dd5a01b3207d3dbd18e2413b/lib/actiontab.h
- `lib/errtab.h`, SHA-256 `1831842c2a024a5098f68d29d7fab6a3f46a2b14ffac9e1c2750d77181052138`: https://raw.githubusercontent.com/linux-audit/audit-userspace/ccd29d145591aba9dd5a01b3207d3dbd18e2413b/lib/errtab.h
- `lib/fieldtab.h`, SHA-256 `0c2f387050c406e0efff2acde741d31c673b36652ffa5b2947a4e7b3ec2f81fe`: https://raw.githubusercontent.com/linux-audit/audit-userspace/ccd29d145591aba9dd5a01b3207d3dbd18e2413b/lib/fieldtab.h
- `lib/ftypetab.h`, SHA-256 `5589603cd09e2a1ef274a18e8a5c9886b4a2fab91a0f29abb26b24bea6f70886`: https://raw.githubusercontent.com/linux-audit/audit-userspace/ccd29d145591aba9dd5a01b3207d3dbd18e2413b/lib/ftypetab.h
- `lib/libaudit.c`, SHA-256 `cbdf4c8fe5cbb652015b756b3066042c9c5311d79fb756307361afe61aea9470`: https://raw.githubusercontent.com/linux-audit/audit-userspace/ccd29d145591aba9dd5a01b3207d3dbd18e2413b/lib/libaudit.c

- Typed operator/filter restrictions additionally reference `kernel/auditfilter.c` at `ce1e0223d8ad4211275c82a17ed6d43ab81e13d9`, SHA-256 `252293259959ebf526c7af63c32f5c4b42712b3e385f4ef5f11f2d70903a1b61`: https://raw.githubusercontent.com/torvalds/linux/ce1e0223d8ad4211275c82a17ed6d43ab81e13d9/kernel/auditfilter.c . This is a source-informed validation matrix, not bundled upstream implementation or kernel execution.
