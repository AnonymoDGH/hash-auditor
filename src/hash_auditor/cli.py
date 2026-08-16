"""Command-line interface for the Hash Auditor."""

from __future__ import annotations

import argparse
import json
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


# ---------------------------------------------------------------------------
# New-module subcommands.
# ---------------------------------------------------------------------------


def cmd_recognize(args: argparse.Namespace) -> None:
    from .hashid import format_candidates, identify_hash
    print(format_candidates(identify_hash(args.hash)))


def cmd_rainbow(args: argparse.Namespace) -> None:
    from .rainbow import RainbowTable, build_table
    if args.lookup:
        table = RainbowTable.load(args.table)
        found = table.lookup(args.lookup)
        if found:
            print(f"[+] FOUND: {found!r}")
        else:
            print("[-] Not covered by this table.")
        return
    table = build_table(args.alphabet, args.length, args.chains,
                        args.chain_length, seed=args.seed)
    path = table.save(args.table)
    stats = table.stats()
    print(f"[+] built {stats['chains']} chains over a "
          f"{stats['keyspace_size']}-password keyspace")
    print(f"[+] coverage: {stats['coverage']:.1%}")
    print(f"[+] saved to {path}")


def cmd_policy(args: argparse.Namespace) -> None:
    from .policy import PRESETS, Policy, check_password, grade_wordlist
    policy = PRESETS[args.preset] if args.preset else Policy()
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            words = [line.strip() for line in fh if line.strip()]
        report = grade_wordlist(words, policy)
        print(f"[*] checked {report['total']} passwords against "
              f"the '{args.preset or 'default'}' policy")
        print(f"[*] passed: {report['passed']}   failed: {report['failed']}"
              f"   pass rate: {report['pass_rate']:.1%}")
        print(f"[*] average score: {report['average_score']}")
        if report["worst"]:
            print("[-] worst offenders: " + ", ".join(report["worst"][:5]))
        return
    rep = check_password(args.password, policy)
    for v in rep.violations:
        print(v.describe())
    print(f"[*] score: {rep.score}  grade: {rep.grade}  "
          f"{'PASS' if rep.passed else 'FAIL'}")


def cmd_generate(args: argparse.Namespace) -> None:
    from .generator import entropy_report, generate
    kwargs: dict = {}
    if args.scheme == "leet":
        kwargs["base"] = args.base or "dragon"
    if args.scheme == "pin":
        kwargs["length"] = args.pin_length
    for i in range(args.count):
        pw = generate(args.scheme, seed=None if args.random else args.seed + i,
                      **kwargs)
        if args.entropy:
            rep = entropy_report(pw, args.scheme)
            print(f"{pw}   ({rep['bits']} bits)")
        else:
            print(pw)


def cmd_breach(args: argparse.Namespace) -> None:
    from .breach import cross_reference, default_corpus, exposure_score
    corpus = default_corpus()
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            words = [line.strip() for line in fh if line.strip()]
        report = cross_reference(words, corpus)
        print(f"[*] checked {report['total']} passwords against the "
              f"simulated breach corpus ({corpus.unique()} entries)")
        print(f"[*] exposed: {report['exposed']} "
              f"({report['exposed_fraction']:.1%})")
        for row in report["rows"][:args.top]:
            if row["found"]:
                print(f"[-] {row['password']!r}: score {row['score']} "
                      f"(matched {row['matched_variant']!r}, "
                      f"rank {row['rank']})")
        return
    rep = exposure_score(args.password, corpus)
    if rep["found"]:
        print(f"[-] EXPOSED: matched {rep['matched_variant']!r} "
              f"(rank {rep['rank']}, score {rep['score']})")
    else:
        print("[+] not found in the simulated breach corpus")


def cmd_mask(args: argparse.Namespace) -> None:
    from .mask import MaskEngine, estimate_mask_time, mask_info
    if args.info:
        info = mask_info(args.mask)
        print(f"[*] mask:      {info['mask']}")
        print(f"[*] length:    {info['length']}")
        print(f"[*] keyspace:  {info['keyspace_size']:,}")
        print(f"[*] entropy:   {info['entropy_bits']} bits")
        est = estimate_mask_time(args.mask, args.rate)
        print(f"[*] worst case at {args.rate:,.0f} H/s: {est['human']}")
        return
    eng = MaskEngine()
    result = eng.crack(args.hash, args.mask, algo=args.algo, limit=args.limit)
    if result["found"]:
        print(f"[+] FOUND: {result['plaintext']!r} "
              f"after {result['attempts']:,} attempts")
    else:
        print(f"[-] not found ({result['attempts']:,} candidates tried)")


def cmd_report(args: argparse.Namespace) -> None:
    from .breach import exposure_score
    from .report import AuditReport
    report = AuditReport(title="hashaudit password audit",
                         timestamp=args.timestamp)
    with open(args.file, encoding="utf-8", errors="replace") as fh:
        passwords = [line.strip() for line in fh if line.strip()]
    for i, pw in enumerate(passwords):
        exposure = exposure_score(pw)
        report.add_password_finding(f"pw{i + 1}", analyze(pw), exposure)
    if args.json:
        print(report.to_json())
    else:
        print(report.to_text())


def cmd_stats(args: argparse.Namespace) -> None:
    from .stats import corpus_report
    with open(args.file, encoding="utf-8", errors="replace") as fh:
        words = [line.strip() for line in fh if line.strip()]
    rep = corpus_report(words)
    print(f"[*] total: {rep['total']}   unique: {rep['unique']}   "
          f"duplicates: {rep['duplicate_rate']:.1%}")
    print(f"[*] length: min {rep['min_length']} / max {rep['max_length']}"
          f" / avg {rep['average_length']}")
    print(f"[*] digit-suffix rate: {rep['digit_suffix_rate']:.1%}   "
          f"capitalization rate: {rep['capitalization_rate']:.1%}")
    if rep["zipf"]["exponent"] is not None:
        print(f"[*] Zipf exponent: {rep['zipf']['exponent']} "
              f"(r^2 = {rep['zipf']['r_squared']})")
    if args.json:
        print(json.dumps(rep, indent=2))


def cmd_similarity(args: argparse.Namespace) -> None:
    from .similarity import detect_mutation
    rep = detect_mutation(args.old, args.new)
    print(f"[*] relationship: {rep['label']}")
    print(f"[*] detail:       {rep['detail']}")
    print(f"[*] similarity:   {rep['similarity']:.2f}   "
          f"edit distance: {rep['distance']}")


def cmd_entropy(args: argparse.Namespace) -> None:
    from .entropy import randomness_report
    rep = randomness_report(args.password)
    print(f"[*] randomness score: {rep['score']}/100 ({rep['verdict']})")
    print(f"[*] shannon entropy:  {rep['shannon_bits']} bits/char")
    print(f"[*] chi-squared:      {rep['chi_squared']}")
    print(f"[*] unique ratio:     {rep['unique_ratio']}")
    print(f"[*] effective bits:   {rep['effective_bits']}")


def cmd_history(args: argparse.Namespace) -> None:
    from .history import PasswordHistory, RotationPolicy, check_rotation
    history = PasswordHistory()
    with open(args.file, encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            pw = line.strip()
            if pw:
                history.add(pw, created_at=float(i))
    policy = RotationPolicy(history_depth=args.depth,
                            min_similarity_gap=args.gap)
    rep = check_rotation(args.new, history, policy)
    if rep["allowed"]:
        print("[+] allowed: no rotation-policy violation")
    else:
        print("[-] rejected:")
        for reason in rep["reasons"]:
            print(f"    - {reason}")
    if rep["closest"]:
        print(f"[*] closest match: {rep['closest']['password']!r} "
              f"(similarity {rep['closest']['similarity']})")


def cmd_parse(args: argparse.Namespace) -> None:
    from .formats import parse_hash_file, split_by_format, to_hashcat
    with open(args.file, encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    records, skipped = parse_hash_file(text)
    print(f"[*] parsed {len(records)} hash(es), skipped {skipped} line(s)")
    groups = split_by_format(records)
    for fmt, recs in sorted(groups.items()):
        print(f"[*] {fmt}: {len(recs)}")
    if args.hashcat:
        print(to_hashcat(records))


def cmd_audit(args: argparse.Namespace) -> None:
    from .audit import audit_batch, audit_password
    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            passwords = [line.strip() for line in fh if line.strip()]
        report = audit_batch(passwords)
        print(f"[*] audited {report['total']} password(s), "
              f"average risk {report['average_risk']}")
        for verdict, count in report["histogram"].items():
            if count:
                print(f"[*] {verdict}: {count}")
        for row in report["ranked"][:args.top]:
            print(f"[-] {row['password']!r}: risk {row['risk_score']} "
                  f"({row['verdict']})")
            for issue in row["issues"][:3]:
                print(f"      - {issue}")
        return
    audit = audit_password(args.password)
    print(f"[*] risk score: {audit['risk_score']}/100 "
          f"-> {audit['verdict']}")
    print(f"[*] strength verdict: {audit['strength']['verdict']}   "
          f"entropy: {audit['strength']['entropy_bits']} bits")
    if audit["exposure"]["found"]:
        print(f"[-] exposed in breach corpus: "
              f"{audit['exposure']['matched_variant']!r} "
              f"(rank {audit['exposure']['rank']})")
    if audit["issues"]:
        print("[-] issues:")
        for issue in audit["issues"]:
            print(f"    - {issue}")
    else:
        print("[+] no issues found")


def cmd_pcfg(args: argparse.Namespace) -> None:
    from .pcfg import generate_pcfg
    guesses = generate_pcfg(args.count)
    for i, guess in enumerate(guesses, 1):
        print(f"{i:5d}. {guess}")


def cmd_combine(args: argparse.Namespace) -> None:
    from .combinator import attack_stats, combinator, hybrid_word_mask
    with open(args.wordlist, encoding="utf-8", errors="replace") as fh:
        words = [line.strip() for line in fh if line.strip()]
    if args.mode == "combinator":
        stream = combinator(words, words)
    else:
        stream = hybrid_word_mask(words, args.mask, position=args.position)
    target = args.hash.strip().lower() if args.hash else None
    import hashlib as _hashlib
    hasher = getattr(_hashlib, args.algo)
    count = 0
    for cand in stream:
        count += 1
        if target and hasher(cand.encode("utf-8")).hexdigest() == target:
            print(f"[+] FOUND: {cand!r} after {count:,} candidates")
            return
        if args.limit and count >= args.limit:
            break
    if target:
        print(f"[-] not found ({count:,} candidates tried)")
    else:
        print(f"[*] generated {count:,} candidates")


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

    p_rec = sub.add_parser("recognize",
                           help="ranked hash-format identification")
    p_rec.add_argument("hash")
    p_rec.set_defaults(fn=cmd_recognize)

    p_rb = sub.add_parser("rainbow", help="build or query a rainbow table")
    p_rb.add_argument("--table", required=True, help="table JSON path")
    p_rb.add_argument("--lookup", default=None, help="md5 hash to look up")
    p_rb.add_argument("--alphabet", default="abcdef")
    p_rb.add_argument("--length", type=int, default=4)
    p_rb.add_argument("--chains", type=int, default=200)
    p_rb.add_argument("--chain-length", type=int, default=24)
    p_rb.add_argument("--seed", type=int, default=0)
    p_rb.set_defaults(fn=cmd_rainbow)

    p_pol = sub.add_parser("policy", help="check a password or file vs a policy")
    p_pol.add_argument("password", nargs="?", default=None)
    p_pol.add_argument("--file", default=None,
                       help="grade every line of this file instead")
    p_pol.add_argument("--preset", default=None,
                       choices=["basic", "corporate", "nist"])
    p_pol.set_defaults(fn=cmd_policy)

    p_gen = sub.add_parser("generate", help="generate passwords/passphrases")
    p_gen.add_argument("--scheme", default="diceware",
                       choices=["diceware", "syllable", "leet", "pin"])
    p_gen.add_argument("--count", type=int, default=1)
    p_gen.add_argument("--seed", type=int, default=0)
    p_gen.add_argument("--random", action="store_true",
                       help="use OS entropy instead of the seed")
    p_gen.add_argument("--base", default=None, help="base word for leet")
    p_gen.add_argument("--pin-length", type=int, default=6)
    p_gen.add_argument("--entropy", action="store_true",
                       help="print per-password entropy estimates")
    p_gen.set_defaults(fn=cmd_generate)

    p_br = sub.add_parser("breach", help="check exposure in the breach corpus")
    p_br.add_argument("password", nargs="?", default=None)
    p_br.add_argument("--file", default=None)
    p_br.add_argument("--top", type=int, default=10)
    p_br.set_defaults(fn=cmd_breach)

    p_mk = sub.add_parser("mask", help="mask attack: info or crack")
    p_mk.add_argument("mask")
    p_mk.add_argument("--info", action="store_true",
                      help="describe the mask instead of cracking")
    p_mk.add_argument("--hash", default=None, help="target hash to crack")
    p_mk.add_argument("--algo", default="md5",
                      choices=["md5", "sha1", "sha224", "sha256",
                               "sha384", "sha512"])
    p_mk.add_argument("--limit", type=int, default=None)
    p_mk.add_argument("--rate", type=float, default=1e6,
                      help="hashes/second for --info time estimates")
    p_mk.set_defaults(fn=cmd_mask)

    p_rep = sub.add_parser("report", help="full audit report for a password file")
    p_rep.add_argument("--file", required=True)
    p_rep.add_argument("--json", action="store_true")
    p_rep.add_argument("--timestamp", default=None,
                       help="fixed timestamp (for reproducible reports)")
    p_rep.set_defaults(fn=cmd_report)

    p_st = sub.add_parser("stats", help="wordlist/corpus statistics")
    p_st.add_argument("--file", required=True)
    p_st.add_argument("--json", action="store_true")
    p_st.set_defaults(fn=cmd_stats)

    p_sim = sub.add_parser("similarity",
                           help="how two passwords are related")
    p_sim.add_argument("old")
    p_sim.add_argument("new")
    p_sim.set_defaults(fn=cmd_similarity)

    p_ent = sub.add_parser("entropy", help="deep randomness analysis")
    p_ent.add_argument("password")
    p_ent.set_defaults(fn=cmd_entropy)

    p_hist = sub.add_parser("history",
                            help="check a new password vs rotation history")
    p_hist.add_argument("new", help="candidate new password")
    p_hist.add_argument("--file", required=True,
                        help="file of previous passwords, one per line")
    p_hist.add_argument("--depth", type=int, default=12)
    p_hist.add_argument("--gap", type=float, default=0.3,
                        help="minimum similarity gap (0 disables)")
    p_hist.set_defaults(fn=cmd_history)

    p_parse = sub.add_parser("parse", help="parse a hash dump file")
    p_parse.add_argument("--file", required=True)
    p_parse.add_argument("--hashcat", action="store_true",
                         help="also print hashcat-style lines")
    p_parse.set_defaults(fn=cmd_parse)

    p_audit = sub.add_parser("audit",
                             help="full integrated risk audit")
    p_audit.add_argument("password", nargs="?", default=None)
    p_audit.add_argument("--file", default=None,
                         help="audit every line of this file")
    p_audit.add_argument("--top", type=int, default=10)
    p_audit.set_defaults(fn=cmd_audit)

    p_pcfg = sub.add_parser("pcfg",
                            help="generate PCFG guesses (probability order)")
    p_pcfg.add_argument("--count", type=int, default=20)
    p_pcfg.set_defaults(fn=cmd_pcfg)

    p_comb = sub.add_parser("combine",
                            help="combinator / hybrid word+mask attack")
    p_comb.add_argument("--wordlist", required=True)
    p_comb.add_argument("--mode", default="combinator",
                        choices=["combinator", "hybrid"])
    p_comb.add_argument("--mask", default="?d?d",
                        help="mask for hybrid mode")
    p_comb.add_argument("--position", default="append",
                        choices=["append", "prepend"])
    p_comb.add_argument("--hash", default=None, help="target hash to crack")
    p_comb.add_argument("--algo", default="md5",
                        choices=["md5", "sha1", "sha224", "sha256",
                                 "sha384", "sha512"])
    p_comb.add_argument("--limit", type=int, default=None)
    p_comb.set_defaults(fn=cmd_combine)

    args = p.parse_args(argv)
    if args.cmd == "policy" and args.password is None and args.file is None:
        p.error("policy needs a password or --file")
    if args.cmd == "breach" and args.password is None and args.file is None:
        p.error("breach needs a password or --file")
    if args.cmd == "mask" and not args.info and args.hash is None:
        p.error("mask needs --info or --hash")
    if args.cmd == "audit" and args.password is None and args.file is None:
        p.error("audit needs a password or --file")
    args.fn(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
