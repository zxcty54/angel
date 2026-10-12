#!/usr/bin/env python3
"""Clean source ZIP or source copy for a PR, never APKs/cache/credentials.
Only Python's standard library. Android Gradle wrapper executable mode kept.
"""
import argparse
import os
from pathlib import Path
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_DIRS = {'.git', '.cache', '.dart_tool', '.idea', '.vscode', '.gradle',
                 '.pub-cache', '.pub', '.temp', '.branches', 'build', 'preview',
                 'delivery', 'coverage', '__pycache__', 'node_modules', 'dist', 'out', 'target'}
EXCLUDED_NAMES = {'.flutter-plugins', '.flutter-plugins-dependencies', '.packages',
                  '.DS_Store', 'local.properties', 'key.properties', 'app-defines.json'}
EXCLUDED_SUFFIXES = {'.apk', '.aab', '.jks', '.keystore', '.pyc', '.hprof', '.log',
                     '.iml', '.zip', '.pem', '.p12', '.key'}


def source_files(root=ROOT):
    root = Path(root)
    for parent, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(name for name in directories
                                if name not in EXCLUDED_DIRS and not (Path(parent)/name).is_symlink())
        for name in sorted(names):
            file = Path(parent)/name
            if (file.is_symlink() or not file.is_file() or name in EXCLUDED_NAMES
                    or file.suffix.lower() in EXCLUDED_SUFFIXES or name == '.env' or name.startswith('.env.')):
                continue
            yield file, file.relative_to(root)


def copy_source(destination, root=ROOT):
    destination = Path(destination).resolve()
    if destination.is_relative_to(Path(root).resolve()):
        raise ValueError('Destination must be outside the source tree; nested copies are unsafe.')
    count = 0
    for file, relative in source_files(root):
        target = destination / relative
        if not target.resolve().is_relative_to(destination):
            raise ValueError('Destination contains an escaping symlink; refusing to overwrite outside it.')
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(file, target)
        if relative.as_posix() == "android/gradlew":
            target.chmod(0o755)
        count += 1
    return count


def package_source(destination, root=ROOT):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for file, relative in source_files(root):
            info = zipfile.ZipInfo.from_file(file, Path('mohalla_charcha')/relative)
            if relative.as_posix() == 'android/gradlew':
                info.external_attr = (0o100755 << 16) | (info.external_attr & 0xffff)
            archive.writestr(info, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
            count += 1
    with zipfile.ZipFile(destination) as archive:
        if archive.testzip() is not None:
            raise ValueError('Source archive integrity check failed.')
    return count


def main():
    parser = argparse.ArgumentParser()
    option = parser.add_mutually_exclusive_group(required=True)
    option.add_argument('--zip', type=Path)
    option.add_argument('--copy-to', type=Path)
    args = parser.parse_args()
    count = package_source(args.zip) if args.zip else copy_source(args.copy_to)
    print(f'Prepared {count} clean source files. No APKs, private config, symlinks or build/cache output.')


if __name__ == '__main__':
    main()
