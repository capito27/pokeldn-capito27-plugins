"""Bring an update into the library from a file: an NSP, or a system update as NCAs in a folder or an archive (zip,
7z, rar, tar). It is checked before it shows, refused when the library already has it, and saved under the name a
download gets (switchlcs.importer).

    POKELDN_PLUGINS=. python -m pokeldn lcs-import -- --file update.nsp
    python lcs_import.py --keys prod.keys --out DIR --file firmware.zip
"""
import argparse
import os
import sys

from pokeldn import progress

from switchlcs import cards, importer, library, nca

STAGES = {"copying": "Copying", "reading": "Reading", "extracting": "Extracting", "checking": "Checking",
          "packing": "Packing"}


def build_parser():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--file", metavar="PATH", action="append", required=True,
                   help="an NSP, an NCA, a folder or an archive; repeatable")
    p.add_argument("--keys", default=None, help="prod.keys (the app passes the file Settings names)")
    p.add_argument("--out", metavar="DIR", help="the library; default the plugin's (Documents/pokeldn/Switch)")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not args.keys:
        print("Choose prod.keys in Settings first: importing an update checks it with them.")
        return 1
    keys = nca.load_keys(os.path.expanduser(args.keys))
    root = library.folder(args.out)
    os.makedirs(root, exist_ok=True)
    library.migrate(root)
    importer.sweep(root)
    jobs, refused = importer.jobs(args.file)
    said = [f"Not imported: {os.path.basename(path)} {why}." for path, why in refused]
    for line in said:
        print(line)
    failed, added = bool(refused), 0
    for job in jobs:
        def moved(stage, done, total, label=job.label):
            if total:
                progress.show(done, total, f"{STAGES.get(stage, stage)} {label}")
        try:
            imported = importer.run(job, root, keys, moved)
        except importer.Refused as error:
            said.append(f"Not imported: {job.label}: {error}.")
            print(said[-1])
            failed = True
            continue
        name = os.path.basename(imported.path)
        said.append(f"Imported {name}")
        print(f"{said[-1]}: {imported.message}")
        cards.checked(name, "valid", imported.message, cards.icon_of(library.Saved(imported.kind, imported.path, ""),
                                                                     keys))
        added += 1
    tone = "ok" if not failed else "warning" if added else "error"
    cards.summary("import", "Last import", {}, tone, said)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
