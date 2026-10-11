import importlib.util
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('source_bundle', ROOT/'source_bundle.py')
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class SourceBundleTests(unittest.TestCase):
    def test_hidden_workflows_included_private_generated_and_symlinks_excluded(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            for name in ['.github/workflows/build.yml', '.gitignore', 'lib/main.dart',
                         'build/app.apk', 'preview/index.html', '.env', 'android/key.properties',
                         'android/local.properties', 'private.jks']:
                file = root/name; file.parent.mkdir(parents=True, exist_ok=True); file.write_text('fixture')
            (root/'link.dart').symlink_to(root/'lib/main.dart')
            names = {str(relative) for _, relative in bundle.source_files(root)}
            self.assertEqual(names, {'.github/workflows/build.yml', '.gitignore', 'lib/main.dart'})

    def test_zip_preserves_wrapper_execute_mode(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)/'source'; root.mkdir()
            wrapper = root/'gradlew'; wrapper.write_text('fixture'); wrapper.chmod(0o755)
            file = Path(t)/'source.zip'
            self.assertEqual(bundle.package_source(file, root), 1)
            with zipfile.ZipFile(file) as archive:
                self.assertIsNone(archive.testzip())
                info = archive.getinfo('mohalla_charcha/gradlew')
                self.assertTrue(info.external_attr >> 16 & stat.S_IXUSR)

    def test_copy_rejects_escaping_destination_symlinks(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)/'source'; destination = Path(t)/'copy'; outside = Path(t)/'outside'
            root.mkdir(); destination.mkdir(); outside.mkdir()
            (root/'lib').mkdir(); (root/'lib/main.dart').write_text('fixture')
            (destination/'lib').symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'escaping'):
                bundle.copy_source(destination, root)
            self.assertFalse((outside/'main.dart').exists())

    def test_copy_rejects_recursive_nested_destination(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            with self.assertRaisesRegex(ValueError, 'outside'):
                bundle.copy_source(root/'nested', root)

    def test_brand_assets_and_native_android12_splash_resources(self):
        project = ROOT.parent
        logo = (project/'assets/branding/logo.png').read_bytes()
        self.assertEqual(logo[:8], b'\x89PNG\r\n\x1a\n')
        self.assertEqual(struct.unpack('>II',logo[16:24]), (1024,1024))
        ET.parse(project/'assets/branding/logo.svg')
        android = project/'android/app/src/main/res'
        for file in ['drawable/mc_splash_logo.xml','drawable/mc_splash_icon.xml',
                     'drawable/mc_launcher_foreground.xml','mipmap-anydpi-v26/ic_launcher.xml',
                     'values/styles.xml','values-v31/styles.xml','values-night-v31/styles.xml']:
            ET.parse(android/file)
        xml = (android/'values-v31/styles.xml').read_text()
        self.assertIn('android:windowSplashScreenAnimatedIcon',xml)
        self.assertIn('@drawable/mc_splash_icon',xml)


if __name__ == '__main__':
    unittest.main()
