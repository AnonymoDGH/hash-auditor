"""Command-line interface for the Hash Auditor."""

from __future__ import annotations

import argparse
import sys

from . import ALGOS, analyze, crack, hash_text, identify


def cmd_check(args: argparse.Namespace) -> None:
    rep = analyze(args.password)
    print(f"[*] length:           {rep['length']}")
    print(f"[*] character classes:{rep['character_classes']}")
    print(f"[*] unique ratio:     {rep['unique_ratio']}")
    print(f"[*] entropy (approx): {rep['entropy_bits']} bits")
    if rep["flags"]:
        for flag in rep["flags"]:
            print(f"[-] {flag}")
    verdict = rep["verdict"]
    mark = {"weak": "[-]", "acceptable": "[~]", "ok": "[+]"}[verdict]
    print(f"{mark} verdict: {verdict}")


def cmd_hash(args: argparse.Namespace) -> None:
    print(hash_text(args.password, args.algo))


def cmd_identify(args: argparse.Namespace) -> None:
    name = identify(args.hash)
    print(name or "[!] unrecognized hash length")


def cmd_crack(args: argparse.Namespace) -> None:
    algo = args.algo or identify(args.hash)
    if not algo:
        print("[!] Could not guess the algorithm; pass --algo.")
        sys.exit(1)
    print(f"[*] Cracking {args.hash} as {algo} with {args.wordlist} ...")
    found = crack(args.hash, args.wordlist, algo, mutate=not args.nomutate)
    if found:
        print(f"[+] FOUND: {found!r}")
    else:
        print("[-] Not in this wordlist.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="hashaudit",
        description="Audit passwords, hash them, identify hashes, crack your own.",
        epilog="Example: hashaudit check 's3cret!'  |  hashaudit crack --hash <md5> --wordlist rockyou.txt",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    p_check = sub.add_parser("check", help="audit a password")
    p_check.add_argument("password")
    p_check.set_defaults(fn=cmd_check)

    p_hash = sub.add_parser("hash", help="compute a hash")
    p_hash.add_argument("password")
    p_hash.add_argument("--algo", default="sha256", choices=sorted(ALGOS))
    p_hash.set_defaults(fn=cmd_hash)

    p_id = sub.add_parser("identify", help="guess algorithm from hash length")
    p_id.add_argument("hash")
    p_id.set_defaults(fn=cmd_identify)

    p_crack = sub.add_parser("crack", help="brute-force a hash with a wordlist")
    p_crack.add_argument("--hash", required=True)
    p_crack.add_argument("--wordlist", required=True)
    p_crack.add_argument("--algo", default=None, choices=sorted(ALGOS))
    p_crack.add_argument("--nomutate", action="store_true",
                         help="skip common mutations (Cap1tals, +123, ...)")
    p_crack.set_defaults(fn=cmd_crack)

    args = p.parse_args(argv)
    args.fn(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
