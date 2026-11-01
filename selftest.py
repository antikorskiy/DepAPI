#!/usr/bin/env python3

'''
Self-test utility for DeepSeek API (unofficial).

Checks environment, tokens, dependencies, imports and optionally performs
a live request against the DeepSeek web API.

Usage:
    python selftest.py            # offline checks only
    python selftest.py --live     # also send a real message
    python selftest.py --live --message "ping"

Exit code: 0 on success, non-zero on failure.
'''

import argparse
import importlib
import os
import sys
import traceback

sys.stdout.reconfigure(encoding='utf-8', errors='replace')
sys.stderr.reconfigure(encoding='utf-8', errors='replace')

HERE = os.path.dirname(os.path.abspath(__file__))
TOKENS_FILE = os.path.join(HERE, 'tokens')
REQUIRED_PACKAGES = ['wasmtime', 'pygments', 'pylatexenc', 'appdirs', 'term_image', 'wcwidth', 'toml', 'flask']

OK = '\u2714'
FAIL = '\u2718'

class Checker:
    def __init__(self):
        self.failures = 0

    def check(self, name, fn):
        try:
            detail = fn()
            print(f"[{OK}] {name}" + (f" — {detail}" if detail else ''))
            return True
        except Exception as e:
            self.failures += 1
            print(f"[{FAIL}] {name} — {e}")
            return False


def check_python():
    if sys.version_info < (3, 8):
        raise RuntimeError(f"Python >= 3.8 required, got {sys.version.split()[0]}")
    return sys.version.split()[0]


def check_packages():
    missing = []
    for pkg in REQUIRED_PACKAGES:
        try:
            importlib.import_module(pkg)
        except Exception:
            missing.append(pkg)
    if missing:
        raise RuntimeError("missing: " + ", ".join(missing))
    return f"{len(REQUIRED_PACKAGES)} ok"


def check_tokens():
    ds, auth = None, None
    if os.path.isfile(TOKENS_FILE):
        with open(TOKENS_FILE, encoding='utf-8') as f:
            lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
        if len(lines) >= 2:
            ds, auth = lines[0], lines[1]
    ds = ds or os.environ.get('DS_SESSION_ID')
    auth = auth or os.environ.get('AUTHORIZATION_TOKEN')
    if not ds or not auth:
        raise RuntimeError("tokens not found (see README)")
    if not auth.lower().startswith('bearer '):
        raise RuntimeError("authorization token must start with 'Bearer '")
    return f"session={ds[:6]}… auth={auth[:13]}…"


def check_imports():
    sys.path.insert(0, HERE)
    from DeepSeekAPI import DeepSeekChat, DeepSeekChatIOMethods  # noqa: F401
    return "DeepSeekAPI imported"


def check_live(message):
    sys.path.insert(0, HERE)
    from DeepSeekAPI import DeepSeekChat
    ds = os.environ.get('DS_SESSION_ID')
    auth = os.environ.get('AUTHORIZATION_TOKEN')
    if os.path.isfile(TOKENS_FILE):
        with open(TOKENS_FILE, encoding='utf-8') as f:
            lines = [ln.strip() for ln in f.read().splitlines() if ln.strip()]
        if len(lines) >= 2:
            ds, auth = lines[0], lines[1]
    chat = DeepSeekChat(ds, auth)
    result = chat.send_message(message, thinking_enabled=False)
    if result is None:
        raise RuntimeError("empty response")
    preview = str(result)
    if len(preview) > 120:
        preview = preview[:120] + '…'
    return preview


def main():
    ap = argparse.ArgumentParser(description='DeepSeek API self-test')
    ap.add_argument('--live', action='store_true', help='perform a live request')
    ap.add_argument('--message', default='ping', help='message for --live')
    args = ap.parse_args()

    print('DeepSeek API self-test')
    print('-' * 40)
    c = Checker()
    c.check('python version', check_python)
    c.check('dependencies', check_packages)
    c.check('tokens', check_tokens)
    c.check('imports', check_imports)
    if args.live:
        c.check(f'live request ({args.message!r})', lambda: check_live(args.message))

    print('-' * 40)
    if c.failures:
        print(f"FAILED: {c.failures} check(s)")
        return 1
    print('OK: all checks passed')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print('\naborted', file=sys.stderr)
        sys.exit(130)
    except Exception:
        traceback.print_exc()
        sys.exit(2)
