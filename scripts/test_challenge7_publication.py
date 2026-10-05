import unittest
from prepare_challenge7_publication import check_text, valid_relative, imports


class Tests(unittest.TestCase):
    def test_selected_source_path_allowed(self):
        self.assertEqual(str(valid_relative('scripts/audit_challenge7_failed_requests.py')),
                         'scripts/audit_challenge7_failed_requests.py')

    def test_raw_and_secret_paths_rejected(self):
        for value in ('../outside', '/absolute', 'cache/result.json', 'run.log', '.env',
                      'challenge7-private-data/cache.txt', 'decoder/target/bin', 'raw.bin'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                valid_relative(value)

    def test_jwt_material_rejected_without_printing_it(self):
        token = 'eyJ' + 'a' * 16 + '.' + 'b' * 16 + '.' + 'c' * 16
        with self.assertRaisesRegex(ValueError, 'intentionally not printed'):
            check_text(token)

    def test_environment_variable_name_is_not_a_secret(self):
        check_text('Read NEAR_INTENTS_JWT from the environment; never save it.')

    def test_personal_filesystem_path_rejected(self):
        path = '/' + 'Users' + '/someone/private/file'
        with self.assertRaises(ValueError):
            check_text(path)

    def test_ast_local_import_inventory(self):
        self.assertEqual(imports('from tool import helper\nimport json, pathlib'),
                         {'tool', 'json', 'pathlib'})


if __name__ == '__main__':
    unittest.main()
