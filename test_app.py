import json
import tempfile
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from app import create_server


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.server = create_server(0, str(Path(self.temp.name) / 'test.sqlite'))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.server.store.db.close()
        self.temp.cleanup()

    def req(self, path, body=None, auth=True, extra=None):
        headers = {'Content-Type': 'application/json', 'X-Demo-Session': 'test-session'}
        if auth:
            headers['X-Operator-Token'] = self.server.token
        headers.update(extra or {})
        req = Request(self.base + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            response = urlopen(req)
        except HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    def test_full_workflow_and_rollback(self):
        attack = {'username': "admin' OR '1'='1", 'password': 'never-log-this-secret'}
        self.assertEqual(self.req('/control/activate', {})[0], 400)
        self.assertEqual(self.req('/control/generate', {})[0], 400)
        self.assertEqual(self.req('/gateway/login', attack)[0], 200)
        self.assertTrue(self.req('/api/auth/login', attack)[1]['ok'])
        rule = self.req('/control/generate', {})[1]
        self.assertEqual(rule['format'], 'banktrap-demo/v1')
        result = self.req('/control/validate', {})[1]
        self.assertEqual([result[x] for x in ['TP','FN','FP','TN']], [8,0,0,12])
        self.assertEqual([x['blocked'] for x in result['known_limitations']], [False,False,True])
        self.assertEqual(self.req('/control/activate', {})[0], 200)
        self.assertEqual(self.req('/gateway/login', attack)[0], 403)
        self.assertEqual(self.req('/gateway/login', {'username': "o'reilly"})[0], 200)
        self.req('/control/disable', {})
        self.assertEqual(self.req('/gateway/login', attack)[0], 200)
        state = self.req('/control/state')[1]
        self.assertNotIn('never-log-this-secret', json.dumps(state))
        self.req('/control/reset', {})
        state = self.req('/control/state')[1]
        self.assertFalse(state['enabled'])
        self.assertEqual(state['events'], [])

    def test_control_boundary_and_input_validation(self):
        self.assertEqual(self.req('/control/state', auth=False)[0], 401)
        self.assertEqual(self.req('/control/reset', {}, auth=False)[0], 401)
        self.assertEqual(self.req('/api/auth/login', {}, extra={'Origin':'https://outside.example'})[0], 403)
        self.assertEqual(self.req('/health', extra={'Host':'outside.example'})[0], 403)
        self.assertEqual(self.req('/api/auth/login', {'username': []})[0], 400)
        self.assertEqual(self.req('/api/auth/login', {'username':'x'*9000})[0], 413)
        self.assertEqual(self.req('/api/transfer', {'amount':100})[0], 401)

    def test_techniques_and_synthetic_transfer(self):
        self.req('/api/admin/users')
        self.assertIsNone(self.req('/control/state')[1]['events'][0]['technique'])
        for _ in range(5):
            self.req('/api/auth/login', {'username':'wrong', 'password':'wrong'})
        self.assertEqual(self.req('/control/state')[1]['events'][0]['technique'], 'T1110.001 (candidate)')
        self.req('/api/auth/login', {'username':'demo-admin', 'password':'demo-canary'})
        self.assertEqual(self.req('/control/state')[1]['events'][0]['technique'], 'T1078 (demo)')
        self.assertEqual(self.req('/api/transfer', {'amount':-1})[0], 400)
        self.assertTrue(self.req('/api/transfer', {'amount':1000})[1]['synthetic'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
