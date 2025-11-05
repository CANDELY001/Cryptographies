#!/usr/bin/env python3
"""Compute MD5 hash of a string or file using hashlib."""

import argparse
import hashlib
import pathlib
import sys

def md5_of_string(s: str) -> str:
    """Return MD5 hex digest of the given string (UTF-8)."""
    h = hashlib.md5()
    h.update(s.encode('utf-8'))
    return h.hexdigest()

def md5_of_file(path: pathlib.Path, chunk_size: int = 8192) -> str:
    """Return MD5 hex digest of the file at path. Reads file in chunks."""
    h = hashlib.md5()
    with path.open('rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def main(argv=None):
    parser = argparse.ArgumentParser(description="Compute MD5 hash of a string or file.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-s', '--string', help='String to hash')
    group.add_argument('-f', '--file', help='Path to file to hash')
    args = parser.parse_args(argv)

    if args.string is not None:
        digest = md5_of_string(args.string)
        print(f"MD5 (string): {digest}")
    else:
        p = pathlib.Path(args.file)
        if not p.exists():
            print("Error: file not found:", p, file=sys.stderr)
            return 2
        digest = md5_of_file(p)
        print(f"MD5 (file {p}): {digest}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
