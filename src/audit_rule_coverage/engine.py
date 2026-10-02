# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
"""Validate audit rule syntax and literal baseline coverage without loading rules."""
import collections
import posixpath
import re
import shlex
from importlib.resources import files as resources
from .common import InputError, Report, mapping, string, logical_lines

LIMITS = ["Literal normalized coverage is not logical equivalence and does not prove telemetry, kernel acceptance or SIEM detection.",
          "Baseline is a frozen complete upstream rule file, including distro-specific paths; missing identities/paths and rule ordering require host validation."]


UID = {'uid','euid','suid','fsuid','auid','loginuid','obj_uid'}
GID = {'gid','egid','sgid','fsgid','obj_gid'}
UNSIGNED = {'pid','ppid','devmajor','devminor','inode','pers','sessionid','saddr_fam'}
SIGNED = {'exit','a0','a1','a2','a3'}
SELINUX = {'subj_type','subj_user','subj_role','subj_sen','subj_clr','obj_type','obj_user','obj_role','obj_lev_low','obj_lev_high'}
# The frozen baseline establishes recognized spellings only, never host ABI support.
KNOWN_SYSCALLS = set(re.findall(r'(?:^|\s)-S\s+(\S+)', resources(__package__).joinpath('baseline.rules').read_text()))
KNOWN_SYSCALLS = {part for value in KNOWN_SYSCALLS for part in value.split(',')} | {'all'}
# Frozen Linux audit_field_valid operator families (kernel/auditfilter.c).
ALL_OPERATORS = {'a0','a1','a2','a3','pers','devminor'}
NO_BIT_OPERATORS = UID | GID | {'pid','msgtype','ppid','devmajor','exit','success','inode',
    'sessionid','subj_sen','subj_clr','obj_lev_low','obj_lev_high','saddr_fam'}
EQUALITY_OPERATORS = {'subj_user','subj_role','subj_type','obj_user','obj_role','obj_type',
    'path','dir','key','loginuid_set','arch','fstype','perm','filetype','field_compare','exe'}

FIELD = re.compile(r'([A-Za-z][A-Za-z0-9_]*)(!=|>=|<=|&=|[=<>&])([^\s]+)')

def numeric(value, label, low=0, high=2**32-1):
    # audit-userspace uses base-0 C conversions; reject partial parses/truncation.
    if len(value)>24 or not re.fullmatch(r'-?(?:0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)',value):
        raise InputError('invalid bounded numeric '+label)
    sign=-1 if value.startswith('-') else 1; digits=value.lstrip('-')
    base=16 if digits.lower().startswith('0x') else 8 if len(digits)>1 and digits.startswith('0') else 10
    number=sign*int(digits,base)
    if not low<=number<=high:raise InputError('numeric value outside supported range: '+label)
    return number

def key_value(value):
    if not value or len(value.encode('utf-8'))>31:raise InputError('audit key must contain 1..31 UTF-8 bytes')

def filter_field(value, option, filter_, report, where):
    match=FIELD.fullmatch(value)
    if not match:raise InputError('invalid audit field: '+value)
    name,op,operand=match.groups()
    if operand[0] in '=<>!&':raise InputError('invalid audit field operator/value: '+value)
    if option=='-C':
        if filter_!='exit' or op not in ('=','!='):raise InputError('inter-field comparisons require exit list and =/!=')
        if name==operand or not ((name in UID and operand in UID) or (name in GID and operand in GID)):
            raise InputError('incompatible inter-field identity comparison')
        return
    if name in NO_BIT_OPERATORS and op in ('&','&='):
        raise InputError('bitwise operator unsupported for selected field: '+name)
    if name in EQUALITY_OPERATORS and op not in ('=','!='):
        raise InputError('selected field requires =/!=: '+name)
    if filter_=='filesystem' and name not in ('fstype','key'):
        raise InputError('filesystem list supports only fstype/key fields')
    if name=='key':
        if op!='=':raise InputError('key supports only equality in selected scope')
        key_value(operand);return
    if name in UID|GID:
        if name in UID and operand in ('unset','-1'):return
        if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]*',operand):
            report.add('identity_resolution','OPEN',where,'Symbolic UID/GID requires host NSS; no identity lookup is performed');return
        if name in UID and operand.startswith('-'):
            numeric(operand,name,-2**31,2**32-1)
            report.add('numeric_representation','OPEN',where,'Negative UID other than unset/-1 is outside portable selected scope');return
        numeric(operand,name);return
    if name in UNSIGNED|SIGNED or name=='success':
        if name in {'exit','devmajor','devminor','inode','success','ppid'} and filter_!='exit':raise InputError(name+' requires exit list')
        if name=='inode' and op not in ('=','!='):raise InputError('inode supports =/!=')
        if name=='exit' and re.fullmatch(r'-?E[A-Z0-9_]+',operand):
            report.add('errno_resolution','OPEN',where,'Symbolic errno table is outside selected numeric scope');return
        if name=='sessionid' and operand in ('unset','-1'):
            report.add('filter_feature','OPEN',where,'Session ID filter needs kernel feature validation');return
        numeric(operand,name,-2**31 if name in SIGNED else 0,
                1 if name=='success' else 2**31-1 if name in ('pid','ppid','exit') else 2**32-1)
        if name in ('sessionid','saddr_fam'):report.add('filter_feature','OPEN',where,'Host feature/address-family availability not verified')
        return
    if name=='arch':
        if op not in ('=','!='):raise InputError('architecture supports =/!=')
        if operand not in ('b32','b64'):report.add('architecture','OPEN',where,'ABI value outside supported b32/b64 scope')
        return
    if name=='perm':
        if op!='=' or filter_ not in ('exit','exclude') or len(operand)>4 or set(operand)-set('rwxaRWXA'):raise InputError('invalid syscall permission set/operator/list')
        return
    if name in ('path','dir','exe'):
        if op not in ('=','!=') or (name in ('path','dir') and op!='='):raise InputError('invalid path operator')
        if name in ('path','dir') and filter_!='exit':raise InputError('watch path requires exit list')
        if not operand.startswith('/') or len(operand.encode('utf-8'))>4096:raise InputError('audit path must be bounded absolute path')
        if posixpath.normpath(operand).strip('/')=='' or any(c in operand for c in '*?['):report.add('path_semantics','OPEN',where,'Root/wildcard path unsupported by selected watch scope')
        return
    if name=='filetype':
        if filter_!='exit' or operand not in ('file','dir','socket','link','character','block','fifo'):raise InputError('invalid filetype/list')
        return
    if name=='msgtype':
        if filter_ not in ('exclude','user'):raise InputError('msgtype requires exclude/user list')
        report.add('message_type','OPEN',where,'Message type table lookup is outside selected numeric scope');return
    if name in SELINUX:
        report.add('selinux_semantics','OPEN',where,'SELinux label/level semantics require host policy validation');return
    report.add('filter_field','OPEN',where,'Field outside selected typed scope: '+name)

def parse(text, report):
    parsed = []; locked = False
    for number, raw in logical_lines(text):
        tokens = shlex.split(raw, comments=True); where = "line:" + str(number)
        if not tokens: continue
        if locked: report.add("immutable_order", "FAIL", where, "Rule follows immutable -e 2")
        if tokens == ['-D'] or tokens == ['-i']:
            report.add("ignore_errors", "FAIL" if tokens == ['-i'] else "PASS", where, "Ignore-error mode masks load errors" if tokens == ['-i'] else "Delete-before-load directive")
            parsed.append((tokens[0], (), (), (), where)); continue
        if tokens[0] in ('-b','-f','-e','-r','--backlog_wait_time'):
            if len(tokens) != 2 or not re.fullmatch(r'[0-9]{1,10}',tokens[1]): raise InputError("invalid audit numeric directive at " + where)
            value = numeric(tokens[1],tokens[0]); option = tokens[0]
            if option=='-f' and value not in (0,1,2):raise InputError('invalid audit failure mode')
            if option == '-b': report.check("buffer", value >= 8192, where, "Backlog buffer: " + tokens[1])
            if option == '-f': report.check("failure_mode", value in (1,2), where, "Failure mode; 2 can halt host, review availability requirements")
            if option == '-e':
                if value not in (0,1,2): raise InputError("invalid audit enabled mode")
                locked = value == 2; report.check("enabled", value != 0, where, "Enabled/immutable mode")
            parsed.append((option, (tokens[1],), (), (), where)); continue
        if tokens[0] not in ('-w','-a','-A'):
            report.add("syntax", "OPEN", where, "Unsupported audit command: " + tokens[0]); continue
        if len(tokens) < 2: raise InputError("missing audit command operand")
        values = collections.defaultdict(list); i = 2
        while i < len(tokens):
            if tokens[i] not in ('-p','-k','-F','-S','-C') or i+1 >= len(tokens): raise InputError("invalid audit option at " + where)
            values[tokens[i]].append(tokens[i+1]); i += 2
        if tokens[0] == '-w':
            if not tokens[1].startswith('/') or len(tokens[1].encode('utf-8'))>4096:
                raise InputError('watch path must be bounded and absolute')
            if posixpath.normpath(tokens[1]).strip('/')=='' or any(c in tokens[1] for c in '*?['):
                report.add('path_semantics','OPEN',where,'Root/wildcard watch path unsupported by selected scope')
            if len(values['-p']) != 1 or not values['-p'][0] or len(values['-p'][0])>4 or set(values['-p'][0])-set('rwxa'):
                report.add("watch_permissions", "FAIL", where, "Watch requires one valid -p permission set")
            for key in values['-k']:key_value(key)
            report.check("watch_key", len(values['-k']) == 1 and bool(values['-k'][0]), where, "Named watch key")
            if values['-F'] or values['-S'] or values['-C']: raise InputError("syscall options on watch")
            normal = (tokens[1], ''.join(sorted(set(''.join(values['-p'])))))
            parsed.append(('-w',normal,tuple(values['-k']),(),where)); continue
        action = tokens[1].split(',')
        if len(action)!=2 or not any(x in ('always','never','possible') for x in action): raise InputError("invalid action/list")
        if not any(x in ('exit','task','user','exclude','filesystem','io_uring') for x in action): raise InputError("invalid audit filter list")
        report.check("syscall_permissions", not values['-p'], where, "Use -F perm=... for syscall filters")
        fields = values['-F'] + values['-C']; calls = sorted(set(c for value in values['-S'] for c in value.split(',')))
        keys = values['-k'] + [f.split('=',1)[1] for f in fields if f.startswith('key=')]
        fields = [f for f in fields if not f.startswith('key=')]
        if len(fields)+len(keys)>63:raise InputError('audit field count exceeds supported 63 slots')
        for option in ('-F','-C'):
            for value in values[option]:filter_field(value,option,next(x for x in action if x not in ('always','never','possible')),report,where)
        for key in keys:key_value(key)
        if len(values['-F'])!=len(set(values['-F'])):report.add('duplicate_fields','OPEN',where,'Duplicate filter fields require review')
        if sum(f.startswith('exe') for f in fields)>1:raise InputError('exe field may only occur once')
        saw_syscall=False
        for index in range(2,len(tokens),2):
            if tokens[index]=='-S':saw_syscall=True
            elif tokens[index]=='-F' and tokens[index+1].startswith(('arch=','arch!=')) and saw_syscall:raise InputError('arch must precede syscall options')
        for call in calls:
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*|[0-9]{1,5}',call):raise InputError('invalid syscall identifier')
            if call not in KNOWN_SYSCALLS:report.add('syscall_spelling','OPEN',where,'Syscall outside frozen spelling set; host ABI table not consulted')
        report.check("rule_key", bool(keys) or 'never' in action or 'exclude' in action, where, "Attribution key on collecting rule")
        if calls and not any(f.startswith('arch=') for f in fields): report.add("architecture", "OPEN", where, "Syscall names without explicit ABI")
        if 'never' in action and not fields: report.add("suppression", "FAIL", where, "Unbounded never filter suppresses auditing")
        elif 'never' in action: report.add("suppression", "OPEN", where, "Suppression/filter ordering needs review")
        if tokens[0]=='-A': report.add("prepend", "OPEN", where, "Prepending changes filter order")
        # Inter-field comparisons (-C) are not identity-name filters (-F).
        # Preserve their option class in literal baseline identities.
        identified_fields=[option+' '+value for option in ('-F','-C') for value in values[option] if not value.startswith('key=')]
        parsed.append(('-a',tuple(sorted(action)),tuple(sorted(identified_fields+['key='+k for k in keys])),tuple(calls),where))
    return parsed

def analyze(snapshot):
    mapping(snapshot, 'snapshot'); text = string(snapshot.get('rules'), 'rules')
    enabled = snapshot.get('check_baseline', True)
    if not isinstance(enabled,bool): raise InputError('check_baseline must be boolean')
    report = Report('AuditRuleCoverage', 'Selected typed audit rule syntax and risk checks'+(' plus complete frozen literal baseline coverage' if enabled else '; baseline coverage disabled'))
    try: actual = parse(text, report)
    except ValueError as exc:
        if isinstance(exc, InputError): raise
        raise InputError(str(exc)) from exc
    if enabled:
        reference = parse(resources(__package__).joinpath('baseline.rules').read_text(), Report('reference','syntax'))
        present = {r[:4] for r in actual}
        for rule in reference:
            if rule[0] not in ('-a','-w'): continue
            report.check('baseline_coverage',rule[:4] in present,rule[4], 'Frozen collecting/filter rule present' if rule[:4] in present else 'Frozen baseline rule absent: '+repr(rule[:4]))
    if not actual: report.add('coverage','OPEN','rules','Empty rules snapshot')
    return report.finish(LIMITS)
