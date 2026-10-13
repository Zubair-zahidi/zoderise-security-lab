"""Read-only learning utilities for files, local web headers, and POSIX permissions."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import re
import socket
import stat
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

IGNORE_DIRS = {'.git', '.venv', 'venv', '__pycache__'}
MAX_FILES = 10000


def hash_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def inventory(root: Path, exclude: Path | None = None) -> dict[str, str]:
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('The target must be a directory.')
    exclude = exclude.resolve() if exclude else None
    result = {}
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS and not (Path(folder)/d).is_symlink())
        for name in sorted(files):
            path = Path(folder)/name
            if path.is_symlink() or not path.is_file() or path.resolve() == exclude:
                continue
            if len(result) >= MAX_FILES:
                raise ValueError(f'Limit reached: choose a folder with at most {MAX_FILES} files.')
            result[path.relative_to(root).as_posix()] = hash_file(path)
    return result


def create_baseline(root: Path, output: Path) -> dict:
    files = inventory(root, output)
    baseline = {'format': 'zoderise-integrity-v1', 'algorithm': 'sha256', 'files': files}
    # Exclusive creation preserves an existing baseline rather than overwriting it.
    with output.open('x', encoding='utf-8') as target:
        json.dump(baseline, target, indent=2, sort_keys=True)
        target.write('\n')
    return {'baseline': str(output), 'files_recorded': len(files)}


def verify_baseline(root: Path, baseline_path: Path) -> dict:
    baseline = json.loads(baseline_path.read_text(encoding='utf-8'))
    if baseline.get('format') != 'zoderise-integrity-v1' or baseline.get('algorithm') != 'sha256':
        raise ValueError('Unsupported baseline format.')
    expected = baseline.get('files')
    if not isinstance(expected, dict) or len(expected) > MAX_FILES:
        raise ValueError('Invalid baseline file list.')
    for name, digest in expected.items():
        path = PurePosixPath(name)
        if (not name or path.is_absolute() or '..' in path.parts or '\\' in name
                or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise ValueError('Invalid path or digest in baseline.')
    current = inventory(root, baseline_path)
    added = sorted(current.keys() - expected.keys())
    removed = sorted(expected.keys() - current.keys())
    modified = sorted(name for name in current.keys() & expected.keys() if current[name] != expected[name])
    return {'matches': not (added or removed or modified), 'added': added, 'removed': removed, 'modified': modified}


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_headers(url: str) -> dict:
    parsed = urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError('Use an HTTP(S) loopback URL without embedded credentials.')
    if parsed.hostname.lower() != 'localhost':
        try:
            literal = ipaddress.ip_address(parsed.hostname)
        except ValueError:
            raise ValueError('Use localhost or an explicit loopback IP address.') from None
        if not literal.is_loopback:
            raise ValueError('Header review is restricted to localhost/loopback lab servers.')
    addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
    if not addresses or not all(ipaddress.ip_address(item[4][0]).is_loopback for item in addresses):
        raise ValueError('Header review is restricted to localhost/loopback lab servers.')
    request = Request(url, method='HEAD', headers={'User-Agent': 'Zoderise-Security-Lab/1.0'})
    try:
        with build_opener(NoRedirects()).open(request, timeout=5) as response:
            headers = response.headers
            status = response.status
    except HTTPError as error:
        if 300 <= error.code < 400:
            error.close()
            raise ValueError('Redirects are not followed; provide the final loopback URL.') from None
        headers, status = error.headers, error.code
        error.close()
    checks = {
        'content_security_policy_present': bool(headers.get('Content-Security-Policy')),
        'nosniff_enabled': headers.get('X-Content-Type-Options', '').lower() == 'nosniff',
        'referrer_policy_present': bool(headers.get('Referrer-Policy')),
        'frame_policy_present': bool(headers.get('X-Frame-Options')) or 'frame-ancestors' in headers.get('Content-Security-Policy', '').lower(),
    }
    if parsed.scheme == 'https':
        checks['hsts_present'] = bool(headers.get('Strict-Transport-Security'))
    return {'status': status, 'transport': parsed.scheme, 'checks': checks,
            'scope': 'Header presence and nosniff review only; no security score or vulnerability claim.'}


def check_permissions(root: Path, include_group: bool = False) -> dict:
    if os.name != 'posix':
        raise ValueError('POSIX permission review requires Linux, macOS, or a compatible POSIX environment.')
    root = root.resolve(strict=True)
    if not root.is_dir():
        raise ValueError('The target must be a directory.')
    findings = []
    examined = 0
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in IGNORE_DIRS and not (Path(folder)/d).is_symlink())
        paths = [Path(folder)] + [Path(folder)/name for name in sorted(files)]
        for path in paths:
            if path.is_symlink():
                continue
            examined += 1
            if examined > MAX_FILES:
                raise ValueError('Permission review limit reached; choose a smaller folder.')
            mode = path.stat().st_mode
            flags = []
            if mode & stat.S_IWOTH:
                flags.append('world-writable')
            if include_group and mode & stat.S_IWGRP:
                flags.append('group-writable')
            if flags:
                findings.append({'path': path.relative_to(root).as_posix(), 'mode': oct(stat.S_IMODE(mode)), 'flags': flags})
    return {'examined': examined, 'findings': findings,
            'scope': 'Permissions to review in context; this does not assess ACLs or overall host security.'}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    baseline = commands.add_parser('baseline', help='Record SHA-256 hashes without overwriting a baseline.')
    baseline.add_argument('root', type=Path)
    baseline.add_argument('--output', type=Path, required=True)
    verify = commands.add_parser('verify', help='Compare a folder with a trusted baseline.')
    verify.add_argument('root', type=Path)
    verify.add_argument('--baseline', type=Path, required=True)
    headers = commands.add_parser('headers', help='Review headers of a loopback web lab server.')
    headers.add_argument('url')
    permissions = commands.add_parser('permissions', help='Read POSIX permission bits; changes no permissions.')
    permissions.add_argument('root', type=Path)
    permissions.add_argument('--include-group', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.command == 'baseline':
            result = create_baseline(args.root, args.output)
        elif args.command == 'verify':
            result = verify_baseline(args.root, args.baseline)
        elif args.command == 'headers':
            result = check_headers(args.url)
        else:
            result = check_permissions(args.root, args.include_group)
        print(json.dumps(result, indent=2))
        return 1 if args.command == 'verify' and not result['matches'] else 0
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(json.dumps({'error': str(error)}), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
