#!/usr/bin/env python3
"""
CRX – FiveM Lua Obfuscator
===========================
Protects your Lua resources by:
  • Encrypting string literals with per-file XOR keys (runtime-decoded)
  • Stripping all comments
  • Removing redundant whitespace

Usage
-----
Single file:
    python3 tools/crx.py resources/my_script/client.lua -o dist/

Entire resource directory (skips fxmanifest.lua):
    python3 tools/crx.py resources/my_script/ -o dist/my_script/

Lua 5.4 mode (use 'lua54 yes' in fxmanifest):
    python3 tools/crx.py client.lua --lua54

In-place (overwrites source files – make a backup first!):
    python3 tools/crx.py resources/my_script/ --inplace

Notes
-----
This is source-level obfuscation, not true encryption.  The script is
still executed by the Lua VM, so a determined reverse-engineer can
always recover the logic with enough effort.  For stronger protection
use the official Cfx.re Keymaster escrow system alongside this tool.
"""

import sys
import random
import argparse
import shutil
from pathlib import Path

# ---------------------------------------------------------------------------
# Tokeniser
# ---------------------------------------------------------------------------

T_STR   = 0   # single/double-quoted string
T_LSTR  = 1   # long string  [[ ... ]]
T_LCMT  = 2   # line comment  -- ...
T_BCMT  = 3   # block comment --[[ ... ]]
T_IDENT = 4   # identifier / keyword
T_NUM   = 5   # number literal
T_OTHER = 6   # everything else (operators, punctuation, whitespace)


def _long_bracket(code: str, i: int):
    """If code[i] is '[', check for a long-bracket opening.

    Returns (level, first_content_pos) if found, else (-1, i).
    """
    if i >= len(code) or code[i] != '[':
        return -1, i
    j, lvl = i + 1, 0
    while j < len(code) and code[j] == '=':
        lvl += 1
        j += 1
    if j < len(code) and code[j] == '[':
        return lvl, j + 1
    return -1, i


def tokenise(code: str) -> list:
    toks, i, n = [], 0, len(code)
    while i < n:
        c = code[i]

        # ── comments ─────────────────────────────────────────────────────────
        if c == '-' and i + 1 < n and code[i + 1] == '-':
            lvl, j = _long_bracket(code, i + 2)
            if lvl >= 0:                                      # --[[ block ]]
                close = ']' + '=' * lvl + ']'
                e = code.find(close, j)
                e = (e + len(close)) if e != -1 else n
                toks.append((T_BCMT, code[i:e]))
                i = e
            else:                                              # -- line
                e = code.find('\n', i)
                e = e if e != -1 else n
                toks.append((T_LCMT, code[i:e]))
                i = e

        # ── long strings ──────────────────────────────────────────────────────
        elif c == '[':
            lvl, j = _long_bracket(code, i)
            if lvl >= 0:
                close = ']' + '=' * lvl + ']'
                e = code.find(close, j)
                e = (e + len(close)) if e != -1 else n
                toks.append((T_LSTR, code[i:e]))
                i = e
            else:
                toks.append((T_OTHER, c))
                i += 1

        # ── quoted strings ────────────────────────────────────────────────────
        elif c in '"\'':
            q, j = c, i + 1
            while j < n:
                if code[j] == '\\':
                    j += 2
                    continue
                if code[j] == q:
                    j += 1
                    break
                if code[j] == '\n':
                    break          # malformed – leave as-is
                j += 1
            toks.append((T_STR, code[i:j]))
            i = j

        # ── identifiers ───────────────────────────────────────────────────────
        elif c.isalpha() or c == '_':
            j = i
            while j < n and (code[j].isalnum() or code[j] == '_'):
                j += 1
            toks.append((T_IDENT, code[i:j]))
            i = j

        # ── numbers ───────────────────────────────────────────────────────────
        elif c.isdigit() or (c == '.' and i + 1 < n and code[i + 1].isdigit()):
            j = i
            if c == '0' and i + 1 < n and code[i + 1] in 'xX':
                j += 2
                while j < n and code[j] in '0123456789abcdefABCDEF':
                    j += 1
            else:
                while j < n and (code[j].isdigit() or code[j] in '.eE'):
                    j += 1
            toks.append((T_NUM, code[i:j]))
            i = j

        else:
            toks.append((T_OTHER, c))
            i += 1

    return toks


# ---------------------------------------------------------------------------
# String decoder
# ---------------------------------------------------------------------------

def _lua_str_bytes(tok: str):
    """Decode a Lua quoted-string token to raw bytes.  Returns None on error."""
    try:
        inner = tok[1:-1]
        out, i = [], 0
        esc_simple = {
            'n': 10, 't': 9,  'r': 13, '\\': 92, '"': 34, "'": 39,
            '0': 0,  'a': 7,  'b': 8,  'f': 12,  'v': 11,
        }
        while i < len(inner):
            if inner[i] == '\\' and i + 1 < len(inner):
                e = inner[i + 1]
                if e in esc_simple:
                    out.append(esc_simple[e])
                    i += 2
                elif e == 'x' and i + 3 < len(inner):
                    out.append(int(inner[i + 2:i + 4], 16))
                    i += 4
                elif e.isdigit():
                    j = i + 1
                    while j < len(inner) and inner[j].isdigit() and j - (i + 1) < 3:
                        j += 1
                    out.append(int(inner[i + 1:j]) & 0xFF)
                    i = j
                else:
                    out.append(ord(e))
                    i += 2
            else:
                b = ord(inner[i])
                out.append(b & 0xFF)
                i += 1
        return bytes(out)
    except Exception:
        return None


def _rand_name(length: int = 8) -> str:
    """Generate a random Lua-safe identifier starting with an underscore."""
    chars = 'abcdefghijklmnopqrstuvwxyz'
    return '_' + ''.join(random.choices(chars, k=length))


def _make_decoder(fn: str, lua54: bool) -> str:
    """Return the one-line Lua decoder injected at the top of every file."""
    if lua54:
        xor_expr = 'b[i]~k[j]'
        unpack_expr = 'table.unpack(r)'
    else:
        xor_expr = 'bit.bxor(b[i],k[j])'
        unpack_expr = '(table.unpack or unpack)(r)'

    return (
        f'local {fn}=function(k,b)'
        f'local r,j={{}},1 '
        f'for i=1,#b do '
        f'r[i]={xor_expr};'
        f'j=j%#k+1 '
        f'end '
        f'return string.char({unpack_expr})'
        f'end\n'
    )


def _encode_string(raw: bytes, key: list, fn: str) -> str:
    """Return a Lua expression that decrypts to *raw* at runtime."""
    enc = [b ^ key[i % len(key)] for i, b in enumerate(raw)]
    k_lit = '{' + ','.join(map(str, key)) + '}'
    b_lit = '{' + ','.join(map(str, enc)) + '}'
    return f'{fn}({k_lit},{b_lit})'


# ---------------------------------------------------------------------------
# Obfuscation pipeline
# ---------------------------------------------------------------------------

def obfuscate(code: str, lua54: bool = False) -> str:
    """Return an obfuscated version of *code*.

    Transformations applied:
      1. Strip line and block comments.
      2. Encrypt non-empty quoted string literals with a per-call XOR key.
      3. Strip leading/trailing blank lines from the output.
    """
    toks = tokenise(code)

    key  = [random.randint(1, 255) for _ in range(16)]
    fn   = _rand_name()

    out          = []
    needs_decoder = False

    for typ, val in toks:
        if typ in (T_LCMT, T_BCMT):
            continue                       # drop comments

        if typ == T_STR:
            raw = _lua_str_bytes(val)
            if raw is not None and len(raw) > 0:
                out.append(_encode_string(raw, key, fn))
                needs_decoder = True
                continue

        out.append(val)

    result = ''.join(out).strip()
    if needs_decoder:
        result = _make_decoder(fn, lua54) + result

    return result


# ---------------------------------------------------------------------------
# File / directory processing
# ---------------------------------------------------------------------------

def process_file(src: Path, dst: Path, lua54: bool) -> None:
    code = src.read_text(encoding='utf-8', errors='replace')
    obf  = obfuscate(code, lua54=lua54)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(obf, encoding='utf-8')
    print(f'  obfuscated  {src}  →  {dst}')


def copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    print(f'  copied      {src}  →  {dst}')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description='CRX – FiveM Lua Obfuscator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument(
        'input', nargs='+',
        help='Lua file(s) or resource directory/ies to obfuscate',
    )
    ap.add_argument(
        '-o', '--output', metavar='DIR',
        help='Output directory (default: alongside source with .crx.lua extension)',
    )
    ap.add_argument(
        '--inplace', action='store_true',
        help='Overwrite source files in-place (make a backup first!)',
    )
    ap.add_argument(
        '--lua54', action='store_true',
        help="Use Lua 5.4 operators (for resources with 'lua54 yes' in fxmanifest)",
    )
    args = ap.parse_args()

    if args.output and args.inplace:
        ap.error('--output and --inplace are mutually exclusive')

    for inp in args.input:
        p = Path(inp)

        if p.is_dir():
            # Collect all Lua files except fxmanifest.lua
            lua_files  = [f for f in p.rglob('*.lua') if f.name != 'fxmanifest.lua']
            other_files = [f for f in p.rglob('*') if f.is_file() and f.suffix != '.lua']
            manifest    = list(p.rglob('fxmanifest.lua'))

            if not lua_files and not manifest:
                print(f'Warning: no Lua files found in {p}', file=sys.stderr)
                continue

            for lua in lua_files:
                rel = lua.relative_to(p)
                if args.inplace:
                    dst = lua
                elif args.output:
                    dst = Path(args.output) / rel
                else:
                    dst = lua.with_suffix('.crx.lua')
                process_file(lua, dst, args.lua54)

            if args.output:
                # Copy fxmanifest and non-Lua assets unchanged
                for f in manifest + other_files:
                    dst = Path(args.output) / f.relative_to(p)
                    copy_file(f, dst)

        elif p.is_file():
            if p.suffix != '.lua':
                print(f'Warning: {p} is not a .lua file – skipped', file=sys.stderr)
                continue
            if args.inplace:
                dst = p
            elif args.output:
                dst = Path(args.output) / p.name
            else:
                dst = p.with_suffix('.crx.lua')
            process_file(p, dst, args.lua54)

        else:
            print(f'Error: {inp} not found', file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    main()
