import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT=Path(__file__).parents[1]
def load(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/file);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
summary=load('summary_advisory','socket-summary.py')
fetch=load('vex_fetch_test','socket-vex-fetch.py')
pipeline=load('vex_pipeline_test','socket-vex-pipeline.py')


def finding(action='monitor'):
    return {'ecosystem':'npm','package':'lodash','version':'4.17.11','id':'CVE-2019-10744','vulnerability':True,'action':action}

def document(status):
    return json.dumps({'@context':'https://openvex.dev/ns/v0.2.0','@id':'urn:synthetic:fixture','author':'Fixture',
                       'timestamp':'2026-11-08T00:00:00Z','version':1,'statements':[{
                           'vulnerability':{'name':'CVE-2019-10744'},'products':[{'@id':'pkg:npm/lodash@4.17.11'}],
                           'status':status,'impact_statement':'Synthetic fixture only','action_statement':'Synthetic fixture only'}]}).encode()


class AdvisoryTests(unittest.TestCase):
    def test_monitor_and_warn_vulnerabilities_are_red_ignore_is_not(self):
        for action,code in [('warn',1),('monitor',1),('error',1),('ignore',0),('unknown',2)]:
            self.assertEqual(summary.advisory_exit_code([finding(action)]),code)
        self.assertEqual(summary.advisory_exit_code([dict(finding(),vulnerability=False)]),0)

    def test_vex_variant_does_not_inherit_native_ignore(self):
        raw=[finding('ignore')]
        result=pipeline.independent_baseline(raw)
        self.assertEqual(result[0]['action'],'monitor')
        self.assertEqual(summary.advisory_exit_code(result),1)
        self.assertEqual(raw[0]['action'],'ignore')

    def test_advisory_summary_and_log_include_monitored_cve(self):
        row=dict(finding(),severity='high',fixed_version='4.17.12',ghsa='')
        with patch.dict(os.environ,{'SOCKET_FAIL_ON_FINDINGS':'true'}):
            self.assertTrue(summary.displayed(row))
            content=summary.render_summary({'data':{'id':'scan'}},[row],[],1,'org','abc')
        self.assertIn('optional failed check',content)
        self.assertIn('CVE-2019-10744',content)


class FeedTests(unittest.TestCase):
    def test_conflicting_documents_in_one_feed_fail_instead_of_first_file_wins(self):
        source=fetch.aggregate('own','myTestOrg0/vexel','a'*40,[('a.json',document('not_affected')),('b.json',document('affected'))])
        with self.assertRaises(ValueError):fetch.vex.evaluate([finding('error')],[source],'urn:product')

    def test_same_feed_provenance_records_every_document(self):
        source=fetch.aggregate('own','myTestOrg0/vexel','a'*40,[('a.json',document('under_investigation'))])
        self.assertEqual(len(source['documents']),1)
        self.assertEqual(len(source['documents'][0]['sha256']),64)
        self.assertEqual(fetch.vex.evaluate([finding('error')],[source],'urn:product')['exit_code'],1)

    def test_priority_configuration_cannot_silently_reorder_sources(self):
        with self.assertRaises(ValueError):fetch.load_sources({'sources':[]},[finding()])

    def test_untrusted_repository_and_traversal_are_rejected(self):
        store=fetch.GitHubStore()
        with self.assertRaises(ValueError):store.file('untrusted/repo','a'*40,'vex.json')
        with self.assertRaises(ValueError):store.file('myTestOrg0/vexel','a'*40,'../secret')

    def test_incomplete_tree_is_not_treated_as_no_exclusions(self):
        class Store:
            def resolve(self,*args):return 'a'*40
            def file(self,*args):return b'{"versions":[{"spec_version":"0.1"}]}'
            def json_api(self,repo,path):
                return [{'name':'npm','type':'dir','sha':'b'*40}] if path.startswith('contents') else {'truncated':True}
        config={'sources':[{'name':n,'repository':'myTestOrg0/vexel','ref':'main'} for n in fetch.ORDER]}
        with self.assertRaises(ValueError):fetch.load_sources(config,[finding()],Store())

    def test_missing_ecosystem_is_explicit_coverage_metadata(self):
        class Store:
            def resolve(self,*args):return 'a'*40
            def file(self,*args):return b'{"versions":[{"spec_version":"0.1"}]}'
            def json_api(self,*args):return [{'name':'golang','type':'dir'}]
        config={'sources':[{'name':n,'repository':'myTestOrg0/vexel','ref':'main'} for n in fetch.ORDER]}
        sources=fetch.load_sources(config,[finding()],Store())
        self.assertEqual(len(sources),3)
        self.assertTrue(all(not s['npm_coverage'] and not s['documents'] for s in sources))


class ObserverTests(unittest.TestCase):
    def test_trace_excludes_environment_and_full_command_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'package.json').write_text('{}');trace=root/'trace.jsonl'
            script="const fs=require('fs'); const cp=require('child_process');fs.createReadStream('package.json').resume();cp.spawnSync('/usr/bin/true',['SECRET_ARGUMENT_123']);"
            env=dict(os.environ,GITHUB_WORKSPACE=directory,SOCKET_TRACE_FILE=str(trace),SECRET_TOKEN='SECRET_ENV_123')
            env.pop('SOCKET_OBSERVER_ROOT_PID',None)
            result=subprocess.run(['node','--import='+str(ROOT/'socket-process-observer.mjs'),'-e',script],cwd=directory,env=env,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr.decode())
            text=trace.read_text()
            self.assertNotIn('SECRET_ARGUMENT_123',text)
            self.assertNotIn('SECRET_ENV_123',text)
            events=[json.loads(x) for x in text.splitlines()]
            self.assertTrue(any(x.get('path')=='package.json' and x['bytes']==2 for x in events))


if __name__=='__main__':unittest.main()
