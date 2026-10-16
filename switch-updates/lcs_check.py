"""Check every update in the library is whole and Nintendo's: each NSP's and each system update ZIP's contents
hashed against their content meta, every signature verified (switchlcs.verify). A file unchanged since a passing
check is not read again unless --again asks; its result is kept in the plugin's data folder.

    POKELDN_PLUGINS=. python -m pokeldn lcs-check
    python lcs_check.py --keys prod.keys --out DIR
"""
import argparse
import os
import sys

from pokeldn import progress

from switchlcs import cards, library, nca


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--keys", default=None, help="prod.keys (the app passes the file Settings names)")
    p.add_argument("--out", metavar="DIR", help="the library; default the plugin's (Documents/pokeldn/Switch)")
    p.add_argument("--again", action="store_true", help="check files that passed before too")
    p.add_argument("--checks", metavar="DIR", help="where the results are kept; default the plugin's data folder")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.keys:
        print("Choose prod.keys in Settings first: checking an update needs them.")
        return 1
    keys_path = os.path.expanduser(args.keys)
    keys = nca.load_keys(keys_path)
    root = library.folder(args.out)
    library.migrate(root)
    entries = library.saved(root)
    if not entries:
        print(f"The library holds no update yet: {root}")
        return 0
    checks = library.load_checks(args.checks)
    counts = {"valid": 0, "invalid": 0, "unchecked": 0}
    for entry in sorted(entries, key=lambda e: os.path.basename(e.path).casefold()):
        name = os.path.basename(entry.path)
        icon = cards.icon_of(entry, keys)
        stamp = library.fingerprint(entry.path, keys_path)
        kept = checks.get(entry.path)
        before = not args.again and kept and kept.get("fingerprint") == stamp and kept.get("state") == "valid"
        if before:
            state, message = kept["state"], kept["message"]
        else:
            title = f"Checking {name}"
            cards.checking(name, icon)
            state, message = library.check(entry, keys, lambda done, total: progress.show(done, total, title))
            checks[entry.path] = {"fingerprint": stamp, "state": state, "message": message}
            library.save_checks(checks, args.checks)
        counts[state] += 1
        mark = {"valid": "OK", "invalid": "BAD", "unchecked": "--"}[state]
        print(f"[{mark}] {name}: {message}" + (" (checked before)" if before else ""))
        cards.checked(name, state, message, icon)
    for path in [p for p in checks if not os.path.exists(p)]:
        del checks[path]
    library.save_checks(checks, args.checks)
    tone = "error" if counts["invalid"] else "warning" if counts["unchecked"] else "ok"
    cards.summary("check", "Last check", {"Complete": counts["valid"], "Damaged or not Nintendo's": counts["invalid"],
                                          "Not checked": counts["unchecked"]}, tone)
    print(f"{counts['valid']} complete, {counts['invalid']} damaged or not Nintendo's, {counts['unchecked']} not "
          "checked.")
    return 1 if counts["invalid"] else 0


if __name__ == "__main__":
    sys.exit(main())
