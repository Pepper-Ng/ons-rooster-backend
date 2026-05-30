from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from .storage import StateStore


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Ontsleutel een ONS Rooster credentialexportbestand lokaal.",
    )
    parser.add_argument("export_file", help="Pad naar het versleutelde exportbestand (.json).")
    parser.add_argument(
        "--passphrase",
        help="Export-passphrase. Als je die weglaat, vraagt de tool er interactief om.",
    )
    args = parser.parse_args(argv)

    export_path = Path(args.export_file)
    if not export_path.exists():
        print(f"Bestand niet gevonden: {export_path}", file=sys.stderr)
        return 1

    try:
        bundle = json.loads(export_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Kon het exportbestand niet lezen: {exc}", file=sys.stderr)
        return 1

    passphrase = args.passphrase
    if passphrase is None:
        passphrase = getpass.getpass("Export-passphrase: ")

    try:
        credentials = StateStore.decrypt_credentials_export(bundle, passphrase)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print(json.dumps(credentials.to_dict(), indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())