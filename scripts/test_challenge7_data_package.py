import gzip
import json
import tempfile
import unittest
from pathlib import Path

from package_challenge7_data import build_group, sanitize_line, selected_files, verify_archive


class DataPackageTests(unittest.TestCase):
    def test_local_paths_only_changed(self):
        root = Path('/example/research')
        self.assertEqual(sanitize_line(b'{"path":"/example/research/notes.jsonl","value":3954182}\n', root),
                         b'{"path":"notes.jsonl","value":3954182}\n')
        self.assertEqual(sanitize_line(b'{"other":"/' + b'Users/person/private/file"}', root),
                         b'{"other":"<local-path>"}')

    def test_rejects_credentials_without_printing_value(self):
        for value in (b'{"Authorization":"Bearer secret-value"}',
                      b'{"access_token":"secret-value"}',
                      b'https://api.example/?api_key=secret-value',
                      b'-----BEGIN OPENSSH ' + b'PRIVATE KEY-----',
                      b'eyJ123456789.' + b'123456789.' + b'123456789'):
            with self.assertRaises(ValueError) as ctx:
                sanitize_line(value, Path('/example'))
            self.assertNotIn('secret-value', str(ctx.exception))

    def test_null_request_and_asset_tokens_allowed(self):
        value = b'{"request":null,"token":"nep141:zec.omft.near","jwt":null}'
        self.assertEqual(sanitize_line(value, Path('/example')), value)

    def test_inventory_and_archive_readback(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data, out = root / 'evidence', root / 'out'
            data.mkdir()
            out.mkdir()
            original = b'{"amount":3954182}\n'
            (data / 'notes.jsonl').write_bytes(original)
            (data / 'run.log').write_text('excluded')
            result = build_group(root, out, 'fixture', ['evidence'])
            rows = [json.loads(line) for line in (out / '.fixture-inventory.jsonl').read_text().splitlines()]
            self.assertEqual(result['files'], 1)
            self.assertEqual(result['excludedFiles'], ['evidence/run.log'])
            self.assertFalse(rows[0]['localPathsSanitized'])
            self.assertEqual((data / 'notes.jsonl').read_bytes(), original)
            verify_archive(out / result['asset'], rows)
            rows[0]['publishedSha256'] = '0' * 64
            with self.assertRaises(ValueError):
                verify_archive(out / result['asset'], rows)

    def test_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'evidence').mkdir()
            (root / 'real.json').write_text('{}')
            (root / 'evidence' / 'link.json').symlink_to(root / 'real.json')
            with self.assertRaises(ValueError):
                selected_files(root, ['evidence'])

    def test_unsafe_file_aborts_build_and_preserves_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'evidence').mkdir()
            (root / 'out').mkdir()
            original = b'{"password":"secret-value"}'
            path = root / 'evidence' / 'bad.json'
            path.write_bytes(original)
            with self.assertRaises(ValueError) as ctx:
                build_group(root, root / 'out', 'fixture', ['evidence'])
            self.assertNotIn('secret-value', str(ctx.exception))
            self.assertEqual(path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
