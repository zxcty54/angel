#!/usr/bin/env python3
"""Create a Telegram-friendly ZIP containing the standalone Android APK."""
import argparse
import hashlib
import os
import zipfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--apk', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    if not os.path.isfile(args.apk):
        parser.error('APK does not exist')
    digest = hashlib.sha256()
    with open(args.apk, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
    apk_name = f'Jungle-Strike-{args.version}.apk'
    os.makedirs(os.path.dirname(args.output) or '.', exist_ok=True)
    with zipfile.ZipFile(args.output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        archive.write(args.apk, apk_name)
        archive.writestr('SHA256SUMS.txt', f"{digest.hexdigest()}  {apk_name}\n")
        archive.writestr(
            'INSTALL.txt',
            'Jungle Strike Android APK\n\n'
            'Extract the APK, open it on your Android device, and approve installation '
            'from this source if Android asks.\n'
            'This build is for testing; it is not a Play Store release.\n',
        )
    print(f'Created {args.output} ({os.path.getsize(args.output)} bytes).')


if __name__ == '__main__':
    main()
