#!/usr/bin/env python3
"""Exactly ONE universal APK in ONE Telegram-sized ZIP; no artifact upload.
The historical filename/function is retained for source/API compatibility.
"""
import argparse
import hashlib
import json
import re
import zipfile
from pathlib import Path

MAX_ZIP_BYTES = 49 * 1024 * 1024
ABIS = ('armeabi-v7a', 'arm64-v8a', 'x86_64')
DISPLAY_NAME = json.loads((Path(__file__).resolve().parents[1]/'branding/app_identity.json').read_text())['display_name']


def package_apks(apk_dir: Path, output_dir: Path, version: str, build: str,
                 backend: str = 'demo', signed: bool = False) -> list[Path]:
    apk = apk_dir / 'app-release.apk'
    if not apk.is_file():
        raise ValueError('No universal app-release.apk found. Build without --split-per-abi.')
    if not re.fullmatch(r'[A-Za-z0-9._-]+', version) or not re.fullmatch(r'[A-Za-z0-9._-]+', build):
        raise ValueError('Version/build must be filename-safe.')
    if backend not in ('demo', 'supabase'):
        raise ValueError('Backend must be demo or supabase.')
    if not zipfile.is_zipfile(apk):
        raise ValueError('app-release.apk is not a valid APK ZIP container.')
    with zipfile.ZipFile(apk) as contents:
        if any(f'lib/{abi}/libflutter.so' not in contents.namelist() for abi in ABIS):
            raise ValueError('The APK must be universal: ARM32, ARM64 and x86_64 Flutter libraries required.')
    filename = f'Bihar-Local-Mohalla-Charcha-v{version}-build-{build}-universal.apk'
    archive = output_dir / filename.replace('.apk', '.zip')
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(p != archive for p in output_dir.glob('*.zip')):
        raise ValueError('Delivery directory contains other ZIPs. Use a clean output directory; only one ZIP may be sent.')
    digest = hashlib.sha256()
    with apk.open('rb') as file:
        for block in iter(lambda: file.read(256 * 1024), b''):
            digest.update(block)
    instructions = (
        f'{DISPLAY_NAME.upper()} | {version} | build {build}\n'
        'ONE UNIVERSAL APK: ARM32 / ARM64 / x86_64\n'
        f'Backend: {backend.upper()}\n'
        f'Signing: {"OWN RELEASE KEY" if signed else "DEVELOPMENT / DEBUG KEY"}\n\n'
        '1. Extract this ZIP. There is exactly one APK, no architecture selection.\n'
        '2. Verify its SHA-256 against SHA256SUMS.txt.\n'
        '3. Install the APK on Android 7.0+ (API 24+).\n'
        '4. Only allow installation from a source you trust.\n'
        '5. On the first launch, see the logo and the 3-step welcome tour.\n'
        '6. Profile > Welcome & app tour reopens the tour later.\n\n'
        'A people-to-people community: no government tickets or official routing.\n'
        'Demo data and ward mappings are illustrative, NOT official records.\n'
        'No Telegram bot token or chat ID is embedded in the application.\n'
        + ('\nDebug signing is for testing only. Changing the signing key requires uninstall/reinstall; uninstall removes local data. Keep a stable release key for production updates.\n' if not signed else '')
    )
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
        output.write(apk, filename)
        output.writestr('SHA256SUMS.txt', f'{digest.hexdigest()}  {filename}\n')
        output.writestr('INSTALL.txt', instructions)
    if archive.stat().st_size > MAX_ZIP_BYTES:
        archive.unlink()
        raise ValueError('Universal APK ZIP exceeds the safe Telegram size limit. Reduce assets; do not silently split it.')
    print(f'Packaged ONE universal APK: {archive.name}, {archive.stat().st_size / 1024 / 1024:.1f} MiB')
    return [archive]


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--apk-dir', type=Path, default=Path('build/app/outputs/flutter-apk'))
    parser.add_argument('--output-dir', type=Path, default=Path('delivery'))
    parser.add_argument('--version', default='1.2.0')
    parser.add_argument('--build', default='local')
    parser.add_argument('--backend', choices=['demo', 'supabase'], default='demo')
    parser.add_argument('--signed', choices=['true', 'false'], default='false')
    args = parser.parse_args()
    try:
        package_apks(args.apk_dir, args.output_dir, args.version, args.build, args.backend, args.signed == 'true')
    except (ValueError, OSError) as error:
        parser.exit(1, f'Packaging failed: {error}\n')
