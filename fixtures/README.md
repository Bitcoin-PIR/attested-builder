# attested-builder fixtures

Golden data for Phase 1 (`utxosnapshot` parser + muhash verification).
Produced 2026-06-12 against the owner's Bitcoin node. All values below
are exact strings copied from `bitcoin-cli` output — the end-to-end
golden test must reproduce the muhash **display hex** byte-for-byte.

Core version for both fixtures: **Bitcoin Core v31.0.0**
(`getnetworkinfo` version `310000`, subversion `/Satoshi:31.0.0/`;
macOS, Homebrew; `dumptxoutset` v2 snapshot format, Core ≥ 28).

---

## 1. Regtest golden fixture (committed here)

File: [`txoutset_regtest_111.dat`](txoutset_regtest_111.dat) (6,861 bytes,
committed — this is the end-to-end test input).

| field | value |
|---|---|
| network | regtest (snapshot network magic `fa bf b5 da`) |
| height | `111` |
| best block hash | `4e4003e955a41b187ad32e26fc837a98ca284df84ca3bbea19e6d164b3ebb3e7` |
| **muhash** | `5b93564046e31a3798231c767eb24e45dd818b77ae022cbe8861e2af9d4a8c09` |
| txouts (coins) | `115` |
| transactions | `113` |
| total_amount | `5550.00000000` |
| bogosize | `8307` |
| `dumptxoutset` coins_written | `115` |
| `dumptxoutset` txoutset_hash | `6ee94e37ca1eeeb0a2905575cd9865ba4a4f5c5b37204c75e67985105b16501b` |
| `dumptxoutset` nchaintx | `117` |
| file sha256 | `c9a51490adb3ce8e89bbf767ec387d21911d954bd819e0338ec4613227ed3a93` |

`muhash` / height / best block / txouts are from
`gettxoutsetinfo muhash` at tip; the `dumptxoutset` row values are from
the `dumptxoutset <path> latest` JSON result (its `base_hash` /
`base_height` matched the same block, `txoutset_hash` is Core's
`hash_serialized_3`, *not* muhash).

Header sanity (first bytes of the file): `7574786f ff` (`utxo\xff`
magic) ‖ `0200` (version 2, LE u16) ‖ `fabfb5da` (regtest message
magic) ‖ 32-byte base block hash (LE — reverses to the display hash
above) ‖ `7300000000000000` (coin count 115, LE u64).

### How it was generated (reproducible recipe, not byte-reproducible)

Throwaway datadir, `bitcoind -regtest -fallbackfee=0.0001 -txindex=1`:

1. `createwallet fixture`; mine 101 blocks to a fresh bech32 address
   (coinbase maturity).
2. Send 4 transactions to fresh wallet addresses of distinct types:
   1.0 BTC → p2wpkh (bech32), 2.0 → **p2tr** (bech32m), 0.5 → **legacy
   p2pkh**, 0.25 → **p2sh-segwit**; mine 1 block (height 102). The
   sends chain off each other's unconfirmed outputs, so the 1.0 p2wpkh
   output and its change are both **spent** by later txs — the set has
   real non-coinbase spends and change outputs.
3. Send a 5th tx, 0.33 → fresh **p2wpkh**, mine 1 block + 7 more
   (height 111).
4. `gettxoutsetinfo muhash`, then
   `dumptxoutset <path> latest`, then `shasum -a 256`.

Final set: 115 coins = 111 coinbase outputs (p2wpkh) + unspent
receives (p2tr 2.0, legacy 0.5, p2sh-segwit 0.25, p2wpkh 0.33) +
wallet change (p2wpkh). Script-compression coverage: case 0 (p2pkh),
case 1 (p2sh), and the raw-script fallback (p2wpkh, p2tr), plus
amount compression across many magnitudes and VARINT heights/coinbase
flags. NOT covered: P2PK cases 2–5 (no P2PK outputs here) — the
`utxosnapshot` unit tests should take those from Core's
`compress_tests.cpp` vectors as PLAN.md Phase 1 step 1 already calls
for.

Note: the fixture is **recipe-reproducible, not byte-reproducible** —
wallet keys, txids and the muhash differ on every regeneration. The
committed `.dat` + the strings above are the canonical golden pair.

---

## 2. Mainnet production snapshots (metadata only — files stay on SSD)

These are the full and delta anchors used by the deployed production
databases:

- full snapshot: height `948454`
- delta snapshot range: `940611 -> 948454`

Files (NOT committed):

- `/Volumes/Bitcoin/data/archive/txoutset_940611.dat`
- `/Volumes/Bitcoin/data/archive/txoutset_948454.dat`

Important: `dumptxoutset`'s `txoutset_hash` is Core's serialized UTXO
set hash, not the MuHash printed by `gettxoutsetinfo muhash`. The
MuHash strings below were collected by temporarily rolling the owner's
node tip to the target height and running `gettxoutsetinfo muhash`
without a height argument.

### Height 940611 (delta base)

| field | value |
|---|---|
| network | mainnet |
| anchor height | `940611` |
| anchor block hash | `000000000000000000002c41243b3d74d135942031ef15f547bca1ce8f85eb99` |
| **muhash** | `aebb29df12e045ef5279036263aba3b8f8e9e816e05b04a58f57e63b3b25756b` |
| txouts (coins) | `164933964` |
| transactions | `114370461` |
| total_amount | `20001682.40568506` |
| bogosize | `12922335176` |
| disk_size | `11929809225` |
| `dumptxoutset` coins_written | `164933964` |
| `dumptxoutset` txoutset_hash | `7735b95d64487636058bb1b1100b77bcfb2101cf3b64296d3efe5a6b0a8f472f` |
| `dumptxoutset` nchaintx | `1322729182` |
| file sha256 | `f864896ea6d9789a7d0f7d21e1405096f4e44a7bd674cdeca1b8ac354980d8c8` |
| file size | `9427476008` bytes |

### Height 948454 (production full snapshot / delta target)

| field | value |
|---|---|
| network | mainnet |
| anchor height | `948454` |
| anchor block hash | `00000000000000000001ef683c02c383315db7e917c69d20f79e05985560a4e4` |
| **muhash** | `cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee` |
| txouts (coins) | `164832143` |
| transactions | `114175147` |
| total_amount | `20026191.77820969` |
| bogosize | `12916260017` |
| disk_size | `11429516552` |
| `dumptxoutset` coins_written | `164832143` |
| `dumptxoutset` txoutset_hash | `76d2152dffaf63f281d424be7895e4d376633e369e9f285e127e8c800cce73cf` |
| `dumptxoutset` nchaintx | `1352911466` |
| file sha256 | `e5ed70c794830d6db2d7ebb7ad3965b126067457a977f370ec5e876139dcf6ff` |
| file size | `9422874286` bytes |

Method note: this node runs without `-coinstatsindex`, so
`gettxoutsetinfo muhash <height>` is unavailable. For each anchor, the
node was temporarily moved to that tip with
`invalidateblock <hash(anchor+1)>`, queried with `gettxoutsetinfo
muhash`, then restored with `reconsiderblock`. Snapshot files were
produced with `bitcoin-cli -rpcclienttimeout=0 -named dumptxoutset
<path> rollback=<height>`.

The delta builder path binds both anchors. The TEE should verify both
snapshot files against the MuHash values above, materialize the two flat
UTXO sets, and compute the deterministic set difference internally:

- `from` anchor: height `940611`, MuHash
  `aebb29df12e045ef5279036263aba3b8f8e9e816e05b04a58f57e63b3b25756b`
- `to` anchor: height `948454`, MuHash
  `cf4fc1f1dd400622a5b6f39eca7f764a30570c30cc668e04f00e8a3356c2a2ee`
- script entry point: `scripts/build-delta-database.sh`

This avoids trusting a host-side block replay log for the delta: the
trusted computation is "two Core snapshots + two MuHashes -> deterministic
plus/minus delta -> Merkle roots/root bundle".

---

## 3. gen_1_onion dust/whale counts (PLAN.md node-task 4)

Re-run 2026-06-12 with `gen_1_onion --data-dir <fresh dir>` (binary
from this branch; OnionPIR entry size 3328 B, 4 partitions) against
**`/Volumes/Bitcoin/data/intermediate/full_948454/utxo_set.bin`** —
the current production full snapshot, **height 948454** (built
2026-05-24). These counts size the documented filter for *that*
snapshot, not the new 953383 anchor above; outputs were written to a
scratch dir and discarded, only the printed stats were kept (they were
never persisted by the original build — that's node-task 4).

Input: `164832143` UTXO entries (11.21 GB raw, 68 B/entry).

| partition | unique script_hashes | dust skipped (≤ 576 sats) | whale (> 100 UTXOs/SPK) |
|---|---|---|---|
| 1 | 13,456,535 | 16,764,702 | 9,857 |
| 2 | 13,464,804 | 18,717,875 | 9,900 |
| 3 | 13,458,270 | 16,385,562 | 9,736 |
| 4 | 13,455,430 | 16,877,381 | 9,974 |
| **total** | **53,835,039** | **68,745,520** | **39,467** |

- *dust skipped* counts individual UTXOs with amount ≤ 576 sats,
  dropped before grouping (`DUST_THRESHOLD` in
  `build/src/gen_1_onion.rs`).
- *unique script_hashes* counts SPK groups with ≥ 1 non-dust UTXO
  (164,832,143 − 68,745,520 = 96,086,623 surviving UTXOs, ≈ 1.79 per
  SPK). Matches the index file's 53,835,039 entries.
- *whale* counts SPK groups exceeding `MAX_UTXOS_PER_SPK = 100`,
  written as sentinel index entries (`FLAG_WHALE`, no chunk data).
- Packed output (discarded): 948,640 OnionPIR entries × 3328 B
  (3.16 GB), 5,100 groups > 3840 B spanning multiple entries (0.01 %).

These are the numbers the `rootbundle` filter-params docs should cite
for the 576-sat dust threshold and 100-UTXO whale cap.
