#!/usr/bin/env python3
"""Stream APK ZIP documents directly to Telegram. No third-party upload actions.

Token/chat secrets are only environment variables. Never log the token or bot URL.
Network failures are NOT blindly retried (a lost response may already be delivered).
Only explicit Telegram 429 responses are retried, respecting retry_after.
"""
import argparse
import http.client
import json
import os
import re
import secrets
import sys
import time
import zipfile
from pathlib import Path

MAX_ZIP_BYTES = 49 * 1024 * 1024
DISPLAY_NAME = json.loads((Path(__file__).resolve().parents[1]/'branding/app_identity.json').read_text())['display_name']


def configuration(env=None):
    env = os.environ if env is None else env
    token = env.get('TELEGRAM_BOT_TOKEN', '').strip()
    chat = (env.get('TELEGRAM_CHAT_ID') or env.get('TELEGRAM_CHAT_NAME') or '').strip()
    thread = env.get('TELEGRAM_THREAD_ID', '').strip()
    if not token or not re.fullmatch(r'[0-9]+:[A-Za-z0-9_-]{20,}', token):
        raise ValueError('Set GitHub Secret TELEGRAM_BOT_TOKEN to a valid bot token.')
    if not re.fullmatch(r'-?[0-9]+|@[A-Za-z][A-Za-z0-9_]{4,}', chat):
        raise ValueError('Set TELEGRAM_CHAT_ID (numeric private/group ID), or TELEGRAM_CHAT_NAME (@public_channel). A private username/chat title will not work.')
    if thread and not re.fullmatch(r'[0-9]+', thread):
        raise ValueError('TELEGRAM_THREAD_ID must be a numeric forum topic ID.')
    return token, chat, thread


def send_document(path: Path, token: str, chat: str, thread: str = '', caption: str = ''):
    if path.stat().st_size > MAX_ZIP_BYTES or not zipfile.is_zipfile(path):
        raise ValueError('Only valid ZIP documents under 49 MiB can be sent.')
    safe_name = re.sub(r'[^A-Za-z0-9._-]', '_', path.name)
    boundary = 'mohalla_' + secrets.token_hex(16)
    fields = {'chat_id': chat, 'caption': caption[:900]}
    if thread:
        fields['message_thread_id'] = thread
    prefix = b''
    for key, value in fields.items():
        prefix += (f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n').encode('utf-8')
    prefix += (f'--{boundary}\r\nContent-Disposition: form-data; name="document"; filename="{safe_name}"\r\nContent-Type: application/zip\r\n\r\n').encode('utf-8')
    suffix = f'\r\n--{boundary}--\r\n'.encode('ascii')
    length = len(prefix) + path.stat().st_size + len(suffix)
    for attempt in range(3):
        conn = http.client.HTTPSConnection('api.telegram.org', timeout=180)
        try:
            conn.putrequest('POST', f'/bot{token}/sendDocument')
            conn.putheader('Content-Type', f'multipart/form-data; boundary={boundary}')
            conn.putheader('Content-Length', str(length))
            conn.endheaders()
            conn.send(prefix)
            with path.open('rb') as f:
                while block := f.read(256 * 1024):
                    conn.send(block)
            conn.send(suffix)
            response = conn.getresponse()
            payload = json.loads(response.read(1024 * 1024))
            if response.status == 429 and attempt < 2:
                retry = min(120, max(1, int(payload.get('parameters', {}).get('retry_after', 5))))
                print(f'Telegram rate limit. Waiting {retry}s.')
                time.sleep(retry)
                continue
            if response.status != 200 or not payload.get('ok'):
                # Do not echo arbitrary upstream strings that might contain secrets.
                code = payload.get('error_code', response.status)
                hints = {400: 'Check chat ID/topic ID and ZIP size.', 401: 'Check bot token.',
                         403: 'Start the bot in private chat, or add it to the group/channel with send permission.'}
                raise RuntimeError(f'Telegram rejected delivery (HTTP {code}). {hints.get(code, "Retry manually after checking the bot settings.")}')
            print(f'Delivered {safe_name}; message_id={payload["result"]["message_id"]}')
            return payload['result']['message_id']
        except (OSError, http.client.HTTPException, json.JSONDecodeError):
            raise RuntimeError('Telegram connection failed or response was invalid. Check the destination before rerunning; the document may already have arrived.') from None
        finally:
            conn.close()
    raise RuntimeError('Telegram remained rate-limited; retry later.')


def archive_to_send(directory: Path) -> Path:
    files = sorted(directory.glob('*.zip'))
    if len(files) != 1:
        raise ValueError('Exactly one universal APK ZIP must be in the delivery directory.')
    path = files[0]
    if not zipfile.is_zipfile(path):
        raise ValueError('Delivery file is not a valid ZIP.')
    with zipfile.ZipFile(path) as archive:
        apks = [info for info in archive.infolist() if not info.is_dir() and info.filename.endswith('.apk')]
        if len(apks) != 1:
            raise ValueError('The delivery ZIP must contain exactly one APK.')
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, default=Path('delivery'))
    parser.add_argument('--check-config', action='store_true')
    args = parser.parse_args()
    token, chat, thread = configuration()
    if args.check_config:
        print('Telegram configuration present. Credentials are not logged.')
        return
    path = archive_to_send(args.directory)
    backend = os.getenv('APP_BACKEND', 'demo').upper()
    signing = 'own release key' if os.getenv('APP_SIGNED') == 'true' else 'development/debug key'
    caption = (f'{DISPLAY_NAME} | {backend} | {signing}\n'
               f'Commit {os.getenv("GITHUB_SHA", "local")[:8]} · Run {os.getenv("GITHUB_RUN_NUMBER", "local")}\n'
               'One universal APK: Android 7+. New logo + first-launch welcome tour. Extract ZIP and install. P2P only; no government ticket routing.')
    send_document(path, token, chat, thread, caption)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError) as e:
        print(f'Delivery failed: {e}', file=sys.stderr)
        sys.exit(1)
