# CRX – FiveM Lua Obfuscator

This repository contains:

- **`tools/crx.py`** – a Python tool that obfuscates your Lua resource files before
  deployment, making client-side memory dumps much harder to read.
- **`resources/my_script/`** – a demo FiveM resource you can use as a starting point.

---

## How it works

`crx.py` runs a Lua tokeniser over your source files and applies:

| Transformation | Effect |
|---|---|
| **String encryption** | Every string literal is XOR-encrypted with a random per-file key and replaced with a runtime-decoder call. Even if a player dumps the script from memory they see encoded byte tables instead of readable strings. |
| **Comment stripping** | All `--` and `--[[ ]]` comments are removed. |

The decoder function is injected automatically at the top of each processed file
using a random identifier (different on every run).

> **Note** – this is source-level obfuscation, not hardware-level encryption.
> A dedicated reverse-engineer can still reconstruct the logic.  For maximum
> protection combine this tool with the
> [official Cfx.re Keymaster escrow](https://keymaster.fivem.net/).

---

## Requirements

- Python 3.8+
- No external packages needed

---

## Usage

### Obfuscate a single file

```bash
python3 tools/crx.py resources/my_script/client.lua -o dist/
```

### Obfuscate an entire resource directory

Copies `fxmanifest.lua` and all non-Lua assets unchanged; obfuscates every
other `.lua` file.

```bash
python3 tools/crx.py resources/my_script/ -o dist/my_script/
```

Then use `dist/my_script/` as your deployed resource.

### Lua 5.4 mode

If your `fxmanifest.lua` contains `lua54 'yes'`, pass `--lua54`:

```bash
python3 tools/crx.py resources/my_script/ -o dist/my_script/ --lua54
```

### In-place (overwrites source — back up first!)

```bash
python3 tools/crx.py resources/my_script/ --inplace
```

### All options

```
positional arguments:
  input           Lua file(s) or resource directory/ies

options:
  -o, --output DIR   Output directory
  --inplace          Overwrite source files in-place
  --lua54            Use Lua 5.4 operators (~ for XOR, table.unpack)
  -h, --help         Show this help message
```

---

## FiveM server setup

Place your **obfuscated** resource in your server's `resources/` folder and add
the following line to `server.cfg`:

```
ensure my_script
```

Then start your server normally.
