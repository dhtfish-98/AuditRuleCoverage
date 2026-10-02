# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
import unittest,json,tempfile,subprocess,sys
from pathlib import Path
from audit_rule_coverage import analyze
from audit_rule_coverage.common import InputError
PROJECT=Path(__file__).resolve().parents[1]
class ReauditTests(unittest.TestCase):
    def good(self):return json.loads((PROJECT/'examples/good.json').read_text())
    def cli(self,snapshot,expected):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'case.json';p.write_text(json.dumps(snapshot))
            r=subprocess.run([sys.executable,'-m','audit_rule_coverage',str(p)],capture_output=True,text=True,timeout=10)
            self.assertEqual(r.returncode,expected,r.stderr)
            self.assertNotIn('Traceback',r.stderr)
            return json.loads(r.stdout)
    def test_kernel_disallows_bit_ops_on_identity_and_selected_numeric_fields(self):
        for field in ('uid','euid','suid','fsuid','auid','loginuid','obj_uid','gid','egid','sgid','fsgid','obj_gid','pid','ppid','devmajor','exit','success','inode','sessionid','saddr_fam','subj_sen','subj_clr','obj_lev_low','obj_lev_high'):
            for op in ('&','&='):
                s={'rules':'-a always,exit -F '+field+op+'1 -k x','check_baseline':False}
                with self.subTest(field=field,op=op):
                    with self.assertRaises(InputError):analyze(s)
        self.assertEqual(self.cli({'rules':'-a always,exit -F uid&=unset -k x','check_baseline':False},2)['status'],'ERROR')
    def test_kernel_equality_only_operator_family(self):
        for field,value in (('filetype','file'),('arch','b64'),('subj_type','label'),('obj_role','label'),('exe','/bin/helper')):
            for op in ('<','>','<=','>=','&','&='):
                with self.subTest(field=field,op=op):
                    with self.assertRaises(InputError):analyze({'rules':'-a always,exit -F '+field+op+value+' -k x','check_baseline':False})
        self.assertEqual(self.cli({'rules':'-a always,exit -F filetype>file -k x','check_baseline':False},2)['status'],'ERROR')
    def test_argument_personality_devminor_bit_ops_remain_supported(self):
        for field in ('a0','a1','a2','a3','pers','devminor'):
            for op in ('&','&='):
                self.assertEqual(analyze({'rules':'-a always,exit -F '+field+op+'0xff -k x','check_baseline':False})['status'],'PASS')
    def test_watch_root_wildcard_and_byte_limit(self):
        for path in ('/','//','/etc/..','/etc/*','/etc/?','/etc/[ab]'):
            s={'rules':'-w '+path+' -p wa -k x','check_baseline':False}
            self.assertEqual(analyze(s)['status'],'OPEN');self.assertEqual(self.cli(s,3)['status'],'OPEN')
        with self.assertRaises(InputError):analyze({'rules':'-w /'+'a'*4096+' -p wa -k x','check_baseline':False})
        self.assertEqual(self.cli({'rules':'-w /etc/shadow -p wa -k x','check_baseline':False},0)['status'],'PASS')
    def test_filesystem_filter_field_family(self):
        with self.assertRaises(InputError):analyze({'rules':'-a always,filesystem -F uid=1 -k x','check_baseline':False})
    def test_interfield_and_identity_name_filters_are_not_same_baseline_identity(self):
        text=(PROJECT/'src/audit_rule_coverage/baseline.rules').read_text()
        locations={'line:'+str(i) for i,x in enumerate(text.splitlines(),1) if '-C auid!=obj_uid' in x}
        self.assertTrue(locations)
        r=analyze({'rules':text.replace('-C auid!=obj_uid','-F auid!=obj_uid')})
        affected=[x for x in r['findings'] if x['check']=='baseline_coverage' and x['evidence'] in locations]
        self.assertEqual(len(affected),len(locations));self.assertTrue(all(x['status']=='FAIL' for x in affected))
        unchanged=analyze({'rules':text})
        self.assertTrue(all(x['status']=='PASS' for x in unchanged['findings'] if x['check']=='baseline_coverage'))
