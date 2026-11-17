#!/usr/bin/env python3
"""Send a packaged Android APK ZIP to Telegram without logging credentials."""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def config():
    token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
    chat = os.environ.get('TELEGRAM_CHAT_ID', '').strip()
    if not token or not chat:
        raise ValueError('Set TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in GitHub Actions secrets.')
    return token, chat


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-config', action='store_true')
    parser.add_argument('--file')
    args = parser.parse_args()
    try:
        token, chat = config()
        if args.check_config:
            print('Telegram configuration is present.')
            return 0
        if not args.file or not os.path.isfile(args.file):
            raise ValueError('ZIP file does not exist.')
        boundary = '----JungleStrikeTelegramUpload'
        filename = os.path.basename(args.file)
        caption = f"Jungle Strike Android APK ZIP · {os.environ.get('BUILD_VERSION', 'manual build')}"
        with open(args.file, 'rb') as apk:
            body = b''.join([
                f'--{boundary}\r\nContent-Disposition: form-data; name="chat_id"\r\n\r\n{chat}\r\n'.encode(),
                f'--{boundary}\r\nContent-Disposition: form-data; name="caption"\r\n\r\n{caption}\r\n'.encode(),
                f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{filename}"\r\nContent-Type: application/zip\r\n\r\n'.encode(),
                apk.read(), f'\r\n--{boundary}--\r\n'.encode(),
            ])
        request = urllib.request.Request(
            f'https://api.telegram.org/bot{token}/sendDocument', data=body,
            headers={'Content-Type': f'multipart/form-data; boundary={boundary}'}, method='POST')
        with urllib.request.urlopen(request, timeout=120) as response:
            result = json.loads(response.read())
        if not result.get('ok'):
            raise RuntimeError('Telegram rejected the upload. Check bot permissions and chat ID.')
        print('APK ZIP delivered to Telegram.')
        return 0
    except (ValueError, OSError, urllib.error.URLError, RuntimeError) as exc:
        print(f'APK delivery failed: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
