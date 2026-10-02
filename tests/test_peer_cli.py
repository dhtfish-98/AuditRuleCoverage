# Author: dhtfish98
# Copyright (c) 2026 dhtfish98
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

class PeerCliTests(unittest.TestCase):
    def test_numeric_rejections_and_open_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'snapshot.json'
            for field,exit_,status in [('uid=>12',2,'ERROR'),('uid='+'1'*5000,2,'ERROR'),('uid=root',3,'OPEN'),('uid=12',0,'PASS')]:
                with self.subTest(field=field[:30]):
                    path.write_text(json.dumps({'rules':'-a always,exit -F arch=b64 -F '+field+' -S open -k access','check_baseline':False}))
                    process=subprocess.run([sys.executable,'-m','audit_rule_coverage',str(path)],capture_output=True,text=True,timeout=10)
                    self.assertEqual(process.returncode,exit_,process.stderr);self.assertNotIn('Traceback',process.stderr)
                    self.assertEqual(json.loads(process.stdout)['status'],status)
