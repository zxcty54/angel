#!/usr/bin/env python3
"""Write transient public app defines and optional private Android signing config."""
import argparse
import base64
import json
import os
from pathlib import Path


def java_escape(value: str) -> str:
    output = ''
    for char in value:
        if char == '\\': output += '\\\\'
        elif char == '\n': output += '\\n'
        elif char == '\r': output += '\\r'
        elif char == '\t': output += '\\t'
        elif ord(char) > 127:
            data = char.encode('utf-16-be')
            output += ''.join('\\u' + data[i:i+2].hex() for i in range(0, len(data), 2))
        else: output += char
    return '\\' + output if output.startswith(' ') else output


def write_defines(backend: str, destination: Path, env=None):
    env = os.environ if env is None else env
    if backend not in ('demo', 'supabase'):
        raise ValueError('Backend must be demo or supabase.')
    data = {'USE_SUPABASE': backend == 'supabase'}
    if backend == 'supabase':
        url = env.get('SUPABASE_URL', '').strip()
        key = env.get('SUPABASE_ANON_KEY', '').strip()
        if not url.startswith('https://') or not key:
            raise ValueError('Supabase builds need Repository Variables SUPABASE_URL and SUPABASE_ANON_KEY (public key only).')
        # A service_role JWT must never be embedded in a client.
        if key.startswith('sb_secret_'):
            raise ValueError('A secret/service-role key cannot be embedded in the app.')
        if key.count('.') == 2:
            try:
                payload = key.split('.')[1]
                claims = json.loads(base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4)))
                if claims.get('role') == 'service_role':
                    raise ValueError('A service-role key cannot be embedded in the app.')
            except (json.JSONDecodeError, UnicodeDecodeError, base64.binascii.Error):
                raise ValueError('The supplied public JWT key is malformed.') from None
        data.update(SUPABASE_URL=url, SUPABASE_ANON_KEY=key)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(data), encoding='utf-8')


def write_signing(root: Path, temp: Path, required=False, env=None) -> bool:
    env = os.environ if env is None else env
    names = ('ANDROID_KEYSTORE_BASE64','ANDROID_STORE_PASSWORD','ANDROID_KEY_ALIAS','ANDROID_KEY_PASSWORD')
    supplied = [bool(env.get(n)) for n in names]
    props = root / 'android/key.properties'
    if not any(supplied):
        props.unlink(missing_ok=True)
        if required:
            raise ValueError('Own release signing is required. Add all four ANDROID_* signing secrets.')
        print('Signing: DEVELOPMENT/debug key. Not a production distribution key.')
        return False
    if not all(supplied):
        raise ValueError('Signing is partially configured. Add all four ANDROID_* signing secrets.')
    temp.mkdir(parents=True, exist_ok=True)
    keystore = temp / 'mohalla-release.jks'
    try:
        raw = base64.b64decode(''.join(env[names[0]].split()), validate=True)
    except base64.binascii.Error:
        raise ValueError('ANDROID_KEYSTORE_BASE64 is invalid.') from None
    if len(raw) < 100:
        raise ValueError('The supplied Android keystore is too small.')
    keystore.write_bytes(raw)
    keystore.chmod(0o600)
    entries = {'storeFile': str(keystore.resolve()), 'storePassword': env[names[1]],
               'keyAlias': env[names[2]], 'keyPassword': env[names[3]]}
    props.write_text('\n'.join(f'{k}={java_escape(v)}' for k,v in entries.items())+'\n', encoding='ascii')
    props.chmod(0o600)
    print('Signing: own release key configured. Private values are not logged.')
    return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', choices=['demo','supabase'], default='demo')
    parser.add_argument('--defines', type=Path, required=True)
    parser.add_argument('--temp', type=Path, required=True)
    parser.add_argument('--root', type=Path, default=Path('.'))
    parser.add_argument('--require-signing', choices=['true','false'], default='false')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        write_defines(args.backend, args.defines)
        signed = write_signing(args.root, args.temp, args.require_signing == 'true')
        if path := os.getenv('GITHUB_OUTPUT'):
            with open(path, 'a', encoding='utf-8') as f:
                f.write(f'signed={str(signed).lower()}\n')
    except ValueError as error:
        parser.exit(1, f'Build configuration failed: {error}\n')
