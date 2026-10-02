import unittest
from importlib.resources import files
from audit_rule_coverage import analyze
from audit_rule_coverage.common import InputError

class AuditTests(unittest.TestCase):
    def simple(self,text):return analyze({'rules':text,'check_baseline':False})
    def test_watch_positive(self):self.assertEqual(self.simple('-w /etc/sudoers -p wa -k policy')['status'],'PASS')
    def test_watch_missing_perm(self):self.assertEqual(self.simple('-w /etc/sudoers -k policy')['status'],'FAIL')
    def test_syscall_perm_error(self):self.assertEqual(self.simple('-a always,exit -p wa -F arch=b64 -S open -k access')['status'],'FAIL')
    def test_arch_missing_open(self):self.assertEqual(self.simple('-a always,exit -S open -k access')['status'],'OPEN')
    def test_immutable_order(self):self.assertEqual(self.simple('-e 2\n-b 8192')['status'],'FAIL')
    def test_suppression(self):self.assertEqual(self.simple('-a never,exit')['status'],'FAIL')
    def test_malformed_key(self):
        with self.assertRaises(InputError):self.simple('-a always,exit -k -F arch=b64')
    def test_empty(self):self.assertEqual(self.simple('')['status'],'OPEN')
    def test_baseline_complete(self):
        raw=files('audit_rule_coverage').joinpath('baseline.rules').read_text().replace('\n-i\n','\n')
        r=analyze({'rules':raw});coverage=[f for f in r['findings'] if f['check']=='baseline_coverage']
        self.assertGreater(len(coverage),200);self.assertTrue(all(f['status']=='PASS' for f in coverage))
    def test_rule_removed_and_order_normalized(self):
        raw=files('audit_rule_coverage').joinpath('baseline.rules').read_text();raw=raw.replace('-a always,exit -F arch=b64 -S execve -S execveat -k process_creation','')
        self.assertTrue(any(f['status']=='FAIL' for f in analyze({'rules':raw})['findings'] if f['check']=='baseline_coverage'))
    def test_invalid_numeric(self):
        with self.assertRaises(InputError):self.simple('-b nope')
    def test_unknown(self):self.assertEqual(self.simple('--unknown value')['status'],'OPEN')

    def test_unknown_abi_not_pass(self):self.assertEqual(self.simple('-a always,exit -F arch=invalid -S open -k test')['status'],'OPEN')
    def test_invalid_syscall_permissions(self):
        with self.assertRaises(InputError):self.simple('-a always,exit -F arch=b64 -F perm=zz -S open -k test')
    def test_unknown_field_not_pass(self):self.assertEqual(self.simple('-a always,exit -F arch=b64 -F future=1 -S open -k test')['status'],'OPEN')


class PeerTypedFieldTests(unittest.TestCase):
    def rule(self, field, option='-F', action='always,exit'):
        return analyze({'rules':'-a '+action+' -F arch=b64 '+option+' '+field+' -S open -k access','check_baseline':False})
    def test_illegal_operator_numeric(self):
        for value in ('uid=>12','uid==12','uid=><12','uid=12trailing','uid=09','uid=１２','uid=0xzz'):
            with self.subTest(value=value),self.assertRaises(InputError):self.rule(value)
    def test_numeric_overflow_and_negatives(self):
        for value in ('uid=4294967296','gid=-1','pid=-123','pid=2147483648','a0=4294967296','exit=-2147483649','success=5','inode>12','uid='+'1'*5000):
            with self.subTest(value=value),self.assertRaises(InputError):self.rule(value)
    def test_valid_numeric_representations(self):
        for value in ('uid=0','uid=0xff','uid=010','uid=4294967295','auid!=unset','auid!=-1','success=1','success=0','a0&=0xff','exit=-13','filetype=file','perm=rwa','exe!=/usr/bin/tool'):
            with self.subTest(value=value):self.assertEqual(self.rule(value)['status'],'PASS')
    def test_nss_and_symbolic_semantics_open(self):
        for value in ('uid=root','gid=wheel','uid=-2','exit=-EACCES','subj_type=cron_t','sessionid=12','saddr_fam=2'):
            with self.subTest(value=value):self.assertEqual(self.rule(value)['status'],'OPEN')
    def test_field_specific_invalid_operator_list(self):
        for value in ('path>/etc','dir!=/etc','exe>/usr/bin/tool','perm!=rw','path=relative','filetype=imaginary','key!=bad'):
            with self.subTest(value=value),self.assertRaises(InputError):self.rule(value)
        with self.assertRaises(InputError):self.rule('exit=1',action='always,task')
        with self.assertRaises(InputError):self.rule('msgtype=1300')
    def test_interfield_supported(self):
        self.assertEqual(self.rule('uid!=euid','-C')['status'],'PASS')
        self.assertEqual(self.rule('gid=egid','-C')['status'],'PASS')
    def test_interfield_invalid(self):
        for value in ('uid>euid','uid=gid','uid=uid','pid=ppid','uid=12'):
            with self.subTest(value=value),self.assertRaises(InputError):self.rule(value,'-C')
        with self.assertRaises(InputError):self.rule('uid!=euid','-C',action='always,task')
    def test_key_bytes_and_utf8(self):
        for key in ('x'*32,'é'*16,'\ud800'):
            with self.subTest(key=repr(key)),self.assertRaises(InputError):analyze({'rules':'-a always,exit -F arch=b64 -S open -k '+key,'check_baseline':False})
    def test_directive_bounds(self):
        for text in ('-b 4294967296','-f 3','-r '+'1'*5000):
            with self.subTest(text=text[:40]),self.assertRaises(InputError):analyze({'rules':text,'check_baseline':False})
    def test_field_count_bound(self):
        with self.assertRaises(InputError):analyze({'rules':'-a always,exit -F arch=b64 '+' -F uid=12'*64+' -S open -k access','check_baseline':False})
    def test_unknown_syscall_open(self):
        self.assertEqual(analyze({'rules':'-a always,exit -F arch=b64 -S future_syscall -k access','check_baseline':False})['status'],'OPEN')
    def test_architecture_order(self):
        with self.assertRaises(InputError):analyze({'rules':'-a always,exit -S open -F arch=b64 -k access','check_baseline':False})
    def test_scope_baseline_disabled(self):
        self.assertIn('baseline coverage disabled',self.rule('uid=12')['scope'])
    def test_frozen_key_literal_coverage(self):
        raw=files('audit_rule_coverage').joinpath('baseline.rules').read_text().replace('-k process_creation','-k changed')
        self.assertTrue(any(f['status']=='FAIL' for f in analyze({'rules':raw})['findings'] if f['check']=='baseline_coverage'))
