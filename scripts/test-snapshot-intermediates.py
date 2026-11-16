#!/usr/bin/env python3
"""Exercise pruning/rebuilding through the real regtest snapshot pipeline."""

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
BUILDER = Path(os.environ.get("BIN", REPO / "target/release/pir-attested-builder")).resolve()
FFI = Path(os.environ.get("ONIONFFI_BIN", REPO / "target/release/onionffi")).resolve()
FIXTURE = REPO / "fixtures/txoutset_regtest_111.dat"
MUHASH = "5b93564046e31a3798231c767eb24e45dd818b77ae022cbe8861e2af9d4a8c09"
PRUNED = {"utxo_set.bin", "onion_index.bin", "merkle_onion_sib_rows_index.bin", "merkle_onion_sib_rows_data.bin"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()  # Tiny regtest files only.


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="snapshot-lifecycle-")
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.wrapper = self.work / "builder-wrapper"
        self.wrapper.write_text(f'''#!{sys.executable}
import os, sys
from pathlib import Path
out = Path(os.environ["OUT_DIR"])
command = sys.argv[1]
prune = os.environ["PRUNE_INTERMEDIATES"] == "1"
ffi = os.environ["RUN_ONION_FFI"] == "1"
if command == "build-onion-data-cuckoo":
    assert (out / "utxo_set.bin").exists() != prune
if command in ("build-root-bundle-payload", "build-root-bundle-payload-v2"):
    assert (out / "onion_index.bin").exists()
    assert (out / "merkle_onion_sib_rows_index.bin").exists()
    assert (out / "merkle_onion_sib_rows_data.bin").exists()
if command in ("write-build-evidence", "write-build-evidence-v2"):
    assert (out / "onion_index.bin").exists() != prune
    assert (out / "merkle_onion_sib_rows_index.bin").exists() != (prune and ffi)
    assert (out / "merkle_onion_sib_rows_data.bin").exists() != (prune and ffi)
    assert (out / "onion_packed_entries.bin").exists()
    assert (out / "onion_index_bins.bin").exists()
if command == os.environ.get("FAIL_COMMAND"):
    sys.exit(70)
os.execv({str(BUILDER)!r}, [{str(BUILDER)!r}, *sys.argv[1:]])
''')
        self.wrapper.chmod(0o755)

    def run_command(self, args, label, env=None, success=True):
        log = self.work / f"{label}.log"
        with log.open("w") as out:
            result = subprocess.run(list(map(str, args)), env=env, stdout=out,
                                    stderr=subprocess.STDOUT, timeout=120)
        if success:
            self.assertEqual(result.returncode, 0, log.read_text()[-12000:])
        else:
            self.assertNotEqual(result.returncode, 0)

    def build(self, label, prune, fail="", ffi=True):
        out = self.work / label
        env = os.environ.copy()
        for key in ("BUILDER_KEY", "TRUSTED_PUBKEYS", "REFERENCE_DATABASE_MANIFEST", "REFERENCE_ALL_ARTIFACTS_MANIFEST"):
            env.pop(key, None)
        env.update({
            "SNAPSHOT": str(FIXTURE), "EXPECTED_MUHASH": MUHASH,
            "NETWORK_MAGIC": "fabfb5da", "ANCHOR_HEIGHT": "111", "CORE_VERSION": "fixture",
            "OUT_DIR": str(out), "SERVER_DB_DIR": str(out / "server-db"),
            "SKIP_CARGO_BUILD": "1", "BIN": str(self.wrapper), "ONIONFFI_BIN": str(FFI),
            "RUN_ONION_FFI": str(int(ffi)), "PRUNE_INTERMEDIATES": str(int(prune)),
            "WRITE_RECEIPT": "0", "WRITE_BUILD_EVIDENCE": "1", "BUILD_EVIDENCE_VERSION": "2" if ffi else "1",
            "ROOTS_ONLY": "0", "STAGE_SERVER_DB": "1", "ONION_ENTRY_SIZE": "3328",
            "PARTITIONS": "4", "PUSH_BATCH_ENTRIES": "256", "ISSUED_AT": "0",
            "TEE_PLATFORM": "none", "TEE_IMAGE_MEASUREMENT": "none", "EMIT_SEV_SNP_QUOTE": "0",
            "BUILDER_GIT_COMMIT": "local-lifecycle-test", "FAIL_COMMAND": fail,
        })
        self.run_command(["bash", REPO / "scripts/build-snapshot-database.sh"], label, env, success=not fail)
        return out

    def test_full_v2_pruning_preserves_payload_serving_files_and_rebuilds(self):
        keep = self.build("keep", False)
        pruned = self.build("pruned", True)
        self.assertEqual((keep / "root-bundle-payload.bin").read_bytes(), (pruned / "root-bundle-payload.bin").read_bytes())
        for folder in ("server-db", "oram-direct-inputs"):
            for old in (keep / folder).iterdir():
                self.assertEqual(old.read_bytes(), (pruned / folder / old.name).read_bytes(), old.name)
        for manifest in ("database.manifest.sha256", "all-artifacts.manifest.sha256"):
            for line in (pruned / manifest).read_text().splitlines():
                expected, name = line.split(None, 1)
                self.assertEqual(digest(pruned / name), expected, name)
        ledger = {}
        for line in (pruned / "pruned-intermediates.tsv").read_text().splitlines():
            name, size, sha, after = line.split("\t")
            self.assertFalse((pruned / name).exists())
            self.assertEqual((keep / name).stat().st_size, int(size))
            self.assertEqual(digest(keep / name), sha)
            ledger[name] = after
        self.assertEqual(set(ledger), PRUNED)
        self.assertEqual(ledger["utxo_set.bin"], "06-build-onion-pack")
        self.assertTrue(all(after == "11-build-root-bundle-payload" for name, after in ledger.items() if name != "utxo_set.bin"))
        self.run_command([BUILDER, "verify-build-evidence", pruned / "build-evidence.bin",
                          "--snapshot", FIXTURE, "--builder-bin", self.wrapper,
                          "--payload", pruned / "root-bundle-payload.bin",
                          "--database-manifest", pruned / "database.manifest.sha256",
                          "--all-artifacts-manifest", pruned / "all-artifacts.manifest.sha256",
                          "--server-db-manifest", pruned / "server-db/MANIFEST.toml",
                          "--expected-muhash", MUHASH, "--expected-anchor-height", "111"], "verify")
        restore = self.work / "restore"
        rebuild = REPO / "scripts/rebuild-snapshot-intermediates.py"
        self.run_command([sys.executable, rebuild, pruned, restore, "--builder", BUILDER], "rebuild")
        for name in PRUNED:
            self.assertEqual((keep / name).read_bytes(), (restore / name).read_bytes())
            self.assertFalse((pruned / name).exists())
        rows = self.work / "rows"
        self.run_command([sys.executable, rebuild, pruned, rows, "--builder", BUILDER,
                          "--kind", "sibling-rows", "--snapshot", self.work / "missing-snapshot"], "rows")
        self.assertEqual(set(p.name for p in rows.iterdir()), {"merkle_onion_sib_rows_index.bin", "merkle_onion_sib_rows_data.bin", "rebuild-report.json"})
        self.run_command([sys.executable, rebuild, pruned, restore, "--builder", BUILDER], "refuse-existing", success=False)
        self.assertEqual((keep / "utxo_set.bin").read_bytes(), (restore / "utxo_set.bin").read_bytes())

        # Wrong recorded hash must fail before any regenerated output is published.
        bad = self.work / "bad-ledger"
        bad.mkdir()
        shutil.copyfile(pruned / "build.env", bad / "build.env")
        (bad / "pruned-intermediates.tsv").write_text(f"utxo_set.bin\t{(keep / 'utxo_set.bin').stat().st_size}\t{'0' * 64}\t06-build-onion-pack\n")
        rejected = self.work / "rejected"
        self.run_command([sys.executable, rebuild, bad, rejected, "--builder", BUILDER, "--kind", "flat"], "reject-hash", success=False)
        self.assertFalse(rejected.exists())

    def test_failed_consumers_keep_their_inputs(self):
        failed_pack = self.build("failed-pack", True, "build-onion-pack")
        self.assertTrue((failed_pack / "utxo_set.bin").is_file())
        self.assertFalse((failed_pack / "pruned-intermediates.tsv").exists())
        failed_payload = self.build("failed-payload", True, "build-root-bundle-payload-v2")
        self.assertFalse((failed_payload / "utxo_set.bin").exists())
        for name in PRUNED - {"utxo_set.bin"}:
            self.assertTrue((failed_payload / name).is_file())

    def test_rows_remain_available_without_ffi(self):
        output = self.build("no-ffi", True, ffi=False)
        for name in ("merkle_onion_sib_rows_index.bin", "merkle_onion_sib_rows_data.bin"):
            self.assertTrue((output / name).is_file())


if __name__ == "__main__":
    unittest.main()
