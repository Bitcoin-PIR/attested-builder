#!/usr/bin/env python3
"""Regenerate pruned snapshot intermediates into a NEW directory and hash-check them."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


KINDS = {
    "flat": ("utxo_set.bin",),
    "onion-index": ("onion_index.bin",),
    "sibling-rows": ("merkle_onion_sib_rows_index.bin", "merkle_onion_sib_rows_data.bin"),
}
ALLOWED = {name for names in KINDS.values() for name in names}


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def rebuild(source, destination, builder, kind="all", snapshot=None):
    source = source.resolve()
    destination = destination.absolute()
    builder = builder.resolve()
    config = dict(line.split("=", 1) for line in (source / "build.env").read_text().splitlines())
    ledger = {}
    for line in (source / "pruned-intermediates.tsv").read_text().splitlines():
        name, size, digest, after = line.split("\t")
        if name not in ALLOWED or name in ledger or not size.isdecimal() or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid pruned-intermediates.tsv record")
        ledger[name] = {"bytes": int(size), "sha256": digest, "after": after}
    names = sorted(ledger) if kind == "all" else list(KINDS[kind])
    if not names or any(name not in ledger for name in names):
        raise ValueError("requested intermediate is not recorded in the pruning ledger")
    # A separate destination also keeps the proof-bound source manifests valid.
    if destination.resolve() == source or source in destination.resolve().parents:
        raise ValueError("rebuild destination must be outside the source build directory")
    destination.mkdir()  # Refuse any existing destination, including an empty one.
    try:
        with tempfile.TemporaryDirectory(prefix=".rebuild-", dir=destination) as tmp:
            work = Path(tmp)

            def run(*args):
                subprocess.run([str(builder), *map(str, args)], check=True)

            if "utxo_set.bin" in names or "onion_index.bin" in names:
                if snapshot is None:
                    snapshot = Path(config["snapshot"])
                    if not snapshot.is_absolute():
                        snapshot = Path(config["repo_root"]) / snapshot
                snapshot = Path(snapshot).resolve()
                run("materialize-utxo-set", snapshot, config["expected_muhash"],
                    work / "utxo_set.bin", config["anchor_height"], work / "chain_anchor.bin")
            if "onion_index.bin" in names:
                run("build-onion-pack", work / "utxo_set.bin", work, config["onion_entry_size"])
            if any(name.startswith("merkle_onion_sib_rows_") for name in names):
                run("build-onion-merkle", source / "onion_index_bin_hashes.bin",
                    source / "onion_data_bin_hashes.bin", work, config["onion_entry_size"])
            # Validate every requested file before publishing any of them.
            for name in names:
                path = work / name
                if path.stat().st_size != ledger[name]["bytes"] or sha256(path) != ledger[name]["sha256"]:
                    raise ValueError(f"regenerated intermediate differs from recorded build: {name}")
            for name in names:
                # Same-filesystem hardlink avoids a second large copy and
                # refuses to overwrite a file created by another process.
                os.link(work / name, destination / name)
            report = {name: ledger[name] for name in names}
            with (destination / "rebuild-report.json").open("x") as out:
                json.dump(report, out, indent=2)
                out.write("\n")
            return report
    except BaseException:
        # Remove only an empty directory created by this invocation. Any
        # already published, verified files remain available on later errors.
        try:
            destination.rmdir()
        except OSError:
            pass
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="build output containing the pruning ledger")
    parser.add_argument("destination", type=Path, help="new directory outside that build output")
    parser.add_argument("--kind", choices=["all", *KINDS], default="all")
    parser.add_argument("--builder", type=Path,
                        default=Path(__file__).resolve().parents[1] / "target/release/pir-attested-builder")
    parser.add_argument("--snapshot", type=Path, help="override the original Core snapshot location")
    args = parser.parse_args()
    try:
        report = rebuild(args.source, args.destination, args.builder, args.kind, args.snapshot)
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")
    print(json.dumps({"verified_intermediates": list(report), "destination": str(args.destination)}))


if __name__ == "__main__":
    main()
