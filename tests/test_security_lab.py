import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_lab import create_baseline, verify_baseline, check_headers, check_permissions


class LabTests(unittest.TestCase):
    def test_non_object_baseline_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            baseline = root/'baseline.json'
            for value in (None, [], 'invalid', 42):
                baseline.write_text(json.dumps(value))
                with self.subTest(value=value), self.assertRaises(ValueError):
                    verify_baseline(root, baseline)

    def test_integrity_changes_and_baseline_exclusion(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'change.txt').write_text('before')
            (root/'remove.txt').write_text('remove')
            baseline = root/'baseline.json'
            create_baseline(root, baseline)
            self.assertTrue(verify_baseline(root, baseline)['matches'])
            (root/'change.txt').write_text('after')
            (root/'remove.txt').unlink()
            (root/'added.txt').write_text('new')
            result = verify_baseline(root, baseline)
            self.assertEqual(result['modified'], ['change.txt'])
            self.assertEqual(result['removed'], ['remove.txt'])
            self.assertEqual(result['added'], ['added.txt'])
            with self.assertRaises(FileExistsError):
                create_baseline(root, baseline)

    def test_untrusted_baseline_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            baseline = root/'baseline.json'
            baseline.write_text(json.dumps({'format': 'zoderise-integrity-v1', 'algorithm': 'sha256', 'files': {'../outside.txt': 'a'*64}}))
            with self.assertRaises(ValueError):
                verify_baseline(root, baseline)

    @unittest.skipIf(os.name == 'nt', 'Symlinks can require additional Windows permission.')
    def test_symlinks_are_excluded(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root/'original').write_text('text')
            (root/'linked').symlink_to(root/'original')
            result = create_baseline(root, root/'baseline.json')
            self.assertEqual(result['files_recorded'], 1)

    def test_headers_read_local_response_and_refuse_redirect(self):
        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                if self.path == '/redirect':
                    self.send_response(302)
                    self.send_header('Location', 'https://example.com/')
                else:
                    self.send_response(200)
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.send_header('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none'")
                    self.send_header('Referrer-Policy', 'no-referrer')
                self.end_headers()
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            url = f'http://127.0.0.1:{server.server_port}'
            result = check_headers(url)
            self.assertTrue(all(result['checks'].values()))
            with self.assertRaises(ValueError):
                check_headers(url+'/redirect')
            with self.assertRaises(ValueError):
                check_headers('http://user:password@127.0.0.1/')
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)

    def test_nonloopback_address_is_rejected(self):
        with self.assertRaises(ValueError):
            check_headers('http://192.0.2.1/')

    @unittest.skipUnless(os.name == 'posix', 'POSIX permissions are not Windows ACLs.')
    def test_permission_findings_do_not_modify_files(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sample = root/'sample.txt'
            sample.write_text('text')
            sample.chmod(0o606)
            result = check_permissions(root)
            self.assertEqual(result['findings'][0]['flags'], ['world-writable'])
            self.assertEqual(sample.stat().st_mode & 0o777, 0o606)


if __name__ == '__main__':
    unittest.main(verbosity=2)
