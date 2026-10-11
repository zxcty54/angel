import base64
import hashlib
import importlib.util
import io
import json
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f'{name}.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


package = module('package_apks')
telegram = module('send_telegram')
config = module('configure_build')
TOKEN = '123456:' + 'a' * 35  # inert test token; never sent to a real network


class DeliveryTests(unittest.TestCase):
    def test_missing_token_rejected_without_echoing_values(self):
        with self.assertRaisesRegex(ValueError, 'TELEGRAM_BOT_TOKEN'):
            telegram.configuration({})

    def test_numeric_chat_and_public_channel_supported(self):
        self.assertEqual(telegram.configuration({'TELEGRAM_BOT_TOKEN': TOKEN, 'TELEGRAM_CHAT_ID': '-100123456789'})[1], '-100123456789')
        self.assertEqual(telegram.configuration({'TELEGRAM_BOT_TOKEN': TOKEN, 'TELEGRAM_CHAT_NAME': '@mohalla_channel'})[1], '@mohalla_channel')

    def test_private_chat_title_does_not_silently_send_elsewhere(self):
        with self.assertRaisesRegex(ValueError, 'numeric'):
            telegram.configuration({'TELEGRAM_BOT_TOKEN': TOKEN, 'TELEGRAM_CHAT_NAME': 'My private chat'})

    def test_invalid_topic_rejected(self):
        with self.assertRaisesRegex(ValueError, 'numeric'):
            telegram.configuration({'TELEGRAM_BOT_TOKEN': TOKEN, 'TELEGRAM_CHAT_ID': '123', 'TELEGRAM_THREAD_ID': 'general'})

    def test_zip_contains_apk_checksum_and_guide(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); apks = root/'apk'; apks.mkdir()
            apk = apks/'app-release.apk'
            with zipfile.ZipFile(apk, 'w') as z:
                z.writestr('AndroidManifest.xml', 'inert packaging test')
                for abi in package.ABIS: z.writestr(f'lib/{abi}/libflutter.so', 'inert library fixture')
            output = package.package_apks(apks, root/'delivery', '1.0.0', '7')
            with zipfile.ZipFile(output[0]) as z:
                self.assertIn('INSTALL.txt', z.namelist())
                self.assertIn('SHA256SUMS.txt', z.namelist())
                payload = next(n for n in z.namelist() if n.endswith('.apk'))
                self.assertEqual(hashlib.sha256(z.read(payload)).hexdigest(), z.read('SHA256SUMS.txt').decode().split()[0])
                self.assertIn('DEVELOPMENT / DEBUG KEY', z.read('INSTALL.txt').decode())

    def test_bad_or_missing_apk_fails_before_upload(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with self.assertRaisesRegex(ValueError, 'No universal'):
                package.package_apks(root, root/'delivery', '1.0.0', '7')
            (root/'app-release.apk').write_text('not an APK')
            with self.assertRaisesRegex(ValueError, 'valid APK'):
                package.package_apks(root, root/'delivery', '1.0.0', '7')

    def test_telegram_uses_streamed_zip_and_does_not_log_token(self):
        with tempfile.TemporaryDirectory() as t:
            file = Path(t)/'app.zip'
            with zipfile.ZipFile(file, 'w') as z: z.writestr('test.txt', 'inert test')
            conn = MagicMock(); response = MagicMock(); response.status = 200
            response.read.return_value = json.dumps({'ok': True, 'result': {'message_id': 17}}).encode()
            conn.getresponse.return_value = response
            capture = io.StringIO()
            with patch.object(telegram.http.client, 'HTTPSConnection', return_value=conn), redirect_stdout(capture):
                result = telegram.send_document(file, TOKEN, '-100123456789', caption='Test only')
            self.assertEqual(result, 17)
            self.assertNotIn(TOKEN, capture.getvalue())
            self.assertGreaterEqual(conn.send.call_count, 3)
            conn.close.assert_called_once()

    def test_no_github_apk_artifact_action(self):
        workflow = (ROOT.parent/'.github/workflows/build-apk-telegram.yml').read_text()
        self.assertNotIn('uses: actions/upload-artifact', workflow)
        self.assertIn('python3 scripts/send_telegram.py', workflow)

    def test_workflow_uses_one_universal_apk_and_trusted_pr_only(self):
        workflow = (ROOT.parent/'.github/workflows/build-apk-telegram.yml').read_text()
        self.assertNotIn('--split-per-abi', workflow)
        self.assertIn('--target-platform android-arm,android-arm64,android-x64', workflow)
        self.assertIn('  pull_request:', workflow)
        self.assertNotIn('  pull_request_target:', workflow)
        self.assertIn('github.event.pull_request.head.repo.full_name == github.repository', workflow)
        self.assertIn('github.event.pull_request.draft == false', workflow)
        self.assertIn('10000 + GITHUB_RUN_NUMBER', workflow)

    def test_sender_rejects_zero_or_multiple_zips(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with self.assertRaisesRegex(ValueError, 'Exactly one'):
                telegram.archive_to_send(root)
            for name in ['one.zip', 'two.zip']:
                with zipfile.ZipFile(root/name, 'w') as z: z.writestr('app.apk', 'inert fixture')
            with self.assertRaisesRegex(ValueError, 'Exactly one'):
                telegram.archive_to_send(root)

    def test_sender_rejects_multiple_apks_in_one_zip(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with zipfile.ZipFile(root/'one.zip', 'w') as z:
                z.writestr('first.apk', 'inert fixture'); z.writestr('second.apk', 'inert fixture')
            with self.assertRaisesRegex(ValueError, 'exactly one APK'):
                telegram.archive_to_send(root)

    def test_sender_selects_exactly_one_apk_zip(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); archive = root/'one.zip'
            with zipfile.ZipFile(archive, 'w') as z:
                z.writestr('universal.apk', 'inert fixture'); z.writestr('INSTALL.txt', 'guide')
            self.assertEqual(telegram.archive_to_send(root), archive)

    def test_packager_requires_all_three_architectures(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with zipfile.ZipFile(root/'app-release.apk', 'w') as z:
                z.writestr('lib/arm64-v8a/libflutter.so', 'inert fixture')
            with self.assertRaisesRegex(ValueError, 'universal'):
                package.package_apks(root, root/'delivery', '1.1.0', '10001')

    def test_packager_rejects_stale_zips(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); out = root/'delivery'; out.mkdir()
            (out/'old.zip').write_text('old inert fixture')
            with zipfile.ZipFile(root/'app-release.apk', 'w') as z:
                for abi in package.ABIS: z.writestr(f'lib/{abi}/libflutter.so', 'inert fixture')
            with self.assertRaisesRegex(ValueError, 'other ZIPs'):
                package.package_apks(root, out, '1.1.0', '10001')

    def test_packager_does_not_split_an_oversized_archive(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); out = root/'delivery'
            with zipfile.ZipFile(root/'app-release.apk', 'w') as z:
                for abi in package.ABIS: z.writestr(f'lib/{abi}/libflutter.so', 'inert fixture')
            with patch.object(package, 'MAX_ZIP_BYTES', 1), self.assertRaisesRegex(ValueError, 'exceeds'):
                package.package_apks(root, out, '1.1.0', '10001')
            self.assertEqual(list(out.glob('*.zip')), [])


class BuildConfigurationTests(unittest.TestCase):
    def test_demo_needs_no_supabase(self):
        with tempfile.TemporaryDirectory() as t:
            p = Path(t)/'defines.json'; config.write_defines('demo', p, {})
            self.assertEqual(json.loads(p.read_text()), {'USE_SUPABASE': False})

    def test_live_requires_url_and_public_key(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ValueError): config.write_defines('supabase', Path(t)/'defines.json', {})

    def test_service_role_never_embedded(self):
        claims = base64.urlsafe_b64encode(json.dumps({'role':'service_role'}).encode()).decode().rstrip('=')
        with tempfile.TemporaryDirectory() as t:
            for key in ['sb_secret_'+'x'*40, 'header.'+claims+'.signature']:
                with self.assertRaisesRegex(ValueError, 'service'):
                    config.write_defines('supabase', Path(t)/'defines.json', {'SUPABASE_URL':'https://test.supabase.co','SUPABASE_ANON_KEY':key})

    def test_release_signing_cannot_be_partially_configured(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); (root/'android').mkdir()
            with self.assertRaisesRegex(ValueError, 'partially'):
                config.write_signing(root, root/'temp', env={'ANDROID_KEY_ALIAS':'release'})
            with self.assertRaisesRegex(ValueError, 'required'):
                config.write_signing(root, root/'temp', required=True, env={})

    def test_private_signing_properties_escaped_and_not_logged(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t); (root/'android').mkdir()
            secret = 'secret\\value\nwithunicodeअ'
            env = {'ANDROID_KEYSTORE_BASE64':base64.b64encode(b'fake keystore'*40).decode(),
                   'ANDROID_STORE_PASSWORD':secret, 'ANDROID_KEY_ALIAS':'release', 'ANDROID_KEY_PASSWORD':secret}
            capture = io.StringIO()
            with redirect_stdout(capture): self.assertTrue(config.write_signing(root, root/'temp', env=env))
            data = (root/'android/key.properties').read_text()
            self.assertIn('\\n', data); self.assertIn('\\u0905', data)
            self.assertNotIn(secret, capture.getvalue())
            self.assertEqual((root/'android/key.properties').stat().st_mode & 0o777, 0o600)


if __name__ == '__main__':
    unittest.main()
