#!/usr/bin/env python3
"""
guardian_set.py — who is allowed to attest, and how many of them does it take?

CLAIM CLASS: "our bridge is secured by N validators and needs k of them to
sign" — the Wormhole Guardian set as recorded by the Wormhole Core Contract on
Solana, decoded from raw account bytes.

RUN: python3 checkers/guardian_set.py --expect-keys 19 --expect-in-force --upgrade-authority

What this answers
-----------------
Every cross-chain bridge rests on a signer set. The public claim is always the
same shape — "19 nodes, 13 signatures required" — and it is two claims wearing
one coat:

  * a claim about a **set**: how many keys are entitled to sign, whether they
    are distinct, and whether the set the contract will actually accept is the
    set being advertised; and
  * a claim about a **threshold**: how many of those keys a message needs.

The first is a fact recorded on chain and this checker settles it. The second
lives in program logic, so this checker does not assert it from a constant it
was told; it counts the signatures on real, accepted attestations and reports
what it found. See "What this cannot tell you" at the bottom, which is printed
by every run.

Where the numbers come from
---------------------------
Nothing here is read from an explorer, an API or a `jsonParsed` response.

  1. **The Core Contract's config account**, at PDA `["Bridge"]`, holds the
     index of the guardian set currently in force, the grace period an
     outgoing set is given, and the message fee. Layout (Borsh, 24 bytes):
     `guardian_set_index: u32 | last_lamports: u64 |
      guardian_set_expiration_time: u32 | fee: u64`.

  2. **Each guardian set account**, at PDA `["GuardianSet", index as u32
     big-endian]`. Layout: `index: u32 | keys: vec<[u8;20]> |
     creation_time: u32 | expiration_time: u32`. The keys are 20-byte
     Ethereum-style addresses, not Solana pubkeys — a guardian signs with
     secp256k1, and the contract stores the keccak address, not the key.

  3. **Signature sets**, the accounts the contract writes while verifying an
     attestation. Layout: `signatures: vec<bool> | hash: [u8;32] |
     guardian_set_index: u32`. One bool per guardian, in guardian order. The
     number of `true`s is how many guardians signed the message the contract
     then accepted. This is the runtime's own record, not a claim by anyone.

The expiration field, and why 0 is not "expired"
------------------------------------------------
`expiration_time == 0` means *no expiry*, not *expired at the epoch*. That is
established here from the chain rather than from documentation: the set the
config account names as current carries 0, and attestations are being verified
against it continuously. If 0 meant "expired" the bridge would not function.
The checker asserts that link (`--expect-in-force`) instead of assuming it, and
`--history` flags **any non-current set that also carries 0**, because such a
set never stops being accepted.

Exit codes
----------
  0  every assertion holds
  1  at least one assertion is false — the claim is wrong
  2  something could not be checked — no verdict
"""

import argparse
import json
import struct
import sys
import time

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import _lib as lib  # noqa: E402
import spl_mint  # noqa: E402


# The Wormhole Core Contract on Solana mainnet-beta, as published by Wormhole
# on https://wormhole.com/docs/products/reference/contract-addresses/ .
# It is a default, not a trusted input: --program overrides it, and every
# address below is derived from whatever program is actually used.
CORE_BRIDGE_MAINNET = "worm2ZoG2kUd4vFXhvjh93UUH596ayRfgQ2MgjNMTth"

# The precompile that actually checks a secp256k1 signature on Solana. Its
# instruction data begins with a one-byte count of the signatures it verifies.
SECP256K1_PROGRAM = "KeccakSecp256k11111111111111111111111111111"

GUARDIAN_KEY_LEN = 20
BRIDGE_CONFIG_LEN = 24

# One accepted attestation, verified on 2026-08-15, used as a fixed control.
# Wormhole splits a verification across transactions — here 6 signatures then
# 7 — which accumulate into a single signature set. Confirmed transactions are
# immutable, so these two signatures mean the same thing in a year's time; the
# signature-set account they wrote does not, because such accounts are closed
# to reclaim their rent.
PINNED_VERIFICATION_TXS = [
    "37FvW2hw4cjGYMq9hJp4HVGVtfpjE1vqbBQymUExhk6xAkbBQY2E3JHGfMNLjMEBpiffAVy"
    "62uhuUxfnyxUZjZnj",
    "RzaSbFsX3w6rZDtite3jbExeoWx7rvFeXH3fhzm1U2DS2CBmFaRYcK65nnKcMojd6Qh6m7i"
    "rdiKMLZmx1jjmo6s",
]


# ---------------------------------------------------------------------------
# Deriving the accounts
# ---------------------------------------------------------------------------


def bridge_config_address(program_id: str) -> str:
    """PDA ["Bridge"] — the account naming the guardian set in force."""
    raw, _bump = lib.find_program_address(
        [b"Bridge"], lib.parse_pubkey(program_id))
    return lib.b58encode(raw)


def guardian_set_address(program_id: str, index: int) -> str:
    """PDA ["GuardianSet", index as big-endian u32].

    Big-endian is not a detail to skim past. Little-endian gives a different,
    perfectly valid-looking address with nothing at it, and "no account here"
    would read as "that set does not exist" — a wrong answer, not a safe one.
    """
    if not isinstance(index, int) or index < 0 or index > 0xFFFFFFFF:
        raise lib.CheckerError(
            f"guardian set index must be a u32, got {index!r}")
    raw, _bump = lib.find_program_address(
        [b"GuardianSet", struct.pack(">I", index)],
        lib.parse_pubkey(program_id))
    return lib.b58encode(raw)


def upgrade_authority_pda(program_id: str) -> str:
    """PDA ["upgrade"] — the address a self-governed Wormhole contract uses.

    If the program's BPF upgrade authority equals this, no key can upgrade the
    program: only the program itself can sign for it, which it does when it
    processes a governance message the guardians signed.
    """
    raw, _bump = lib.find_program_address(
        [b"upgrade"], lib.parse_pubkey(program_id))
    return lib.b58encode(raw)


# ---------------------------------------------------------------------------
# Decoding the accounts
# ---------------------------------------------------------------------------


def decode_bridge_config(data: bytes) -> dict:
    """`guardian_set_index u32 | last_lamports u64 | expiry u32 | fee u64`."""
    if len(data) != BRIDGE_CONFIG_LEN:
        raise lib.CheckerError(
            f"a Wormhole bridge config account is exactly {BRIDGE_CONFIG_LEN} "
            f"bytes; this one is {len(data)}. Either this is not the config "
            "account or the layout assumed here is wrong.")
    cur = lib.Cursor(data, "bridge config")
    return {
        "guardian_set_index": cur.u32(),
        "last_lamports": cur.u64(),
        "guardian_set_expiration_time": cur.u32(),
        "fee": cur.u64(),
    }


def decode_guardian_set(data: bytes) -> dict:
    """`index u32 | keys vec<[u8;20]> | creation_time u32 | expiration_time u32`.

    Refuses trailing bytes. A guardian set account whose length does not equal
    the length its own key count implies is not a guardian set account, and
    reporting a key list out of it would be inventing evidence.
    """
    cur = lib.Cursor(data, "guardian set")
    index = cur.u32()
    count = cur.u32()
    if count > 512:
        raise lib.CheckerError(
            f"this account claims {count} guardian keys, which is not "
            "credible. The layout assumed here does not match this account.")
    keys = ["0x" + cur.take(GUARDIAN_KEY_LEN).hex() for _ in range(count)]
    creation_time = cur.u32()
    expiration_time = cur.u32()
    if cur.remaining:
        raise lib.CheckerError(
            f"guardian set: {cur.remaining} bytes left over after decoding "
            f"{count} keys. The layout assumed here does not match.")
    return {
        "index": index,
        "count": count,
        "keys": keys,
        "distinct": len(set(keys)),
        "creation_time": creation_time,
        "expiration_time": expiration_time,
    }


def decode_signature_set(data: bytes) -> dict:
    """`signatures vec<bool> | hash [u8;32] | guardian_set_index u32`.

    One flag per guardian slot. `signed` is how many guardians the runtime
    recorded as having signed the message.
    """
    cur = lib.Cursor(data, "signature set")
    count = cur.u32()
    if count > 512:
        raise lib.CheckerError(
            f"this account claims {count} signature slots; the layout assumed "
            "here does not match this account.")
    flags = list(cur.take(count))
    for i, flag in enumerate(flags):
        if flag not in (0, 1):
            raise lib.CheckerError(
                f"signature set: slot {i} holds {flag}, which is not a bool. "
                "This is not a signature set account.")
    digest = cur.take(32)
    index = cur.u32()
    if cur.remaining:
        raise lib.CheckerError(
            f"signature set: {cur.remaining} bytes left over. The layout "
            "assumed here does not match.")
    return {
        "slots": count,
        "signed": sum(flags),
        "flags": "".join("1" if f else "0" for f in flags),
        "hash": digest.hex(),
        "guardian_set_index": index,
    }


def fmt_time(seconds: int) -> str:
    if not seconds:
        return "0 (no expiry)"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


# ---------------------------------------------------------------------------
# Reading the chain
# ---------------------------------------------------------------------------


def read_guardian_set(program_id: str, index: int, url=None) -> dict:
    address = guardian_set_address(program_id, index)
    account = lib.get_account(address, url=url)
    if account["owner"] != program_id:
        raise lib.CheckerError(
            f"the account at {address} is owned by {account['owner']}, not by "
            f"{program_id}. It is not this program's guardian set.")
    decoded = decode_guardian_set(account["data"])
    decoded["address"] = address
    if decoded["index"] != index:
        raise lib.CheckerError(
            f"the guardian set account derived for index {index} says its own "
            f"index is {decoded['index']}. Derivation and content disagree; "
            "no verdict can rest on that.")
    return decoded


def walk_history(program_id: str, url=None, limit: int = 64) -> list:
    """Every guardian set from index 0 up to the first one that is not there.

    Stops at the first gap. Guardian set indices are allocated consecutively,
    so a gap is the end; if one were ever skipped this walk would end early,
    which can only make the history reported *shorter* than the truth. It
    cannot invent a set that does not exist.
    """
    sets = []
    for index in range(limit):
        try:
            sets.append(read_guardian_set(program_id, index, url=url))
        except lib.CheckerError as exc:
            if "no account exists" in str(exc):
                break
            raise
    return sets


def read_verification(program_id: str, tx_signature: str, url=None) -> dict:
    """Decode one `verify_signatures` transaction. Immutable, so publishable.

    A confirmed Solana transaction never changes, while the signature-set
    account it writes is routinely closed to reclaim its rent. So the durable
    evidence for a threshold is the transaction, not the account.

    Two independent readings, which must agree:

      * the **secp256k1 precompile** instruction, whose first data byte is the
        number of signatures the runtime itself verified; and
      * the **core contract** instruction, tag 7, followed by one signed byte
        per guardian slot: the position of that guardian's signature in the
        precompile instruction, or -1 for a guardian who did not sign here.

    If the count of non-negative slots does not equal the precompile's count,
    the reading is wrong and this raises rather than reporting a number.
    """
    tx = lib.rpc("getTransaction",
                 [tx_signature,
                  {"encoding": "json", "maxSupportedTransactionVersion": 0}],
                 url=url)
    if tx is None:
        raise lib.CheckerError(
            f"transaction {tx_signature} was not found. Either the signature "
            "is wrong or this endpoint's history does not reach it.")
    if tx.get("meta", {}).get("err"):
        raise lib.CheckerError(
            f"transaction {tx_signature} failed on chain: "
            f"{tx['meta']['err']}. A failed transaction verified nothing.")

    message = tx["transaction"]["message"]
    keys = message["accountKeys"]
    precompile_count = None
    slots = None
    signature_set = None

    for ins in message["instructions"]:
        program = keys[ins["programIdIndex"]]
        data = lib.b58decode(ins["data"]) if ins["data"] else b""
        if program == SECP256K1_PROGRAM and data:
            precompile_count = data[0]
        elif program == program_id and data and data[0] == 7:
            raw = data[1:]
            slots = [int.from_bytes(bytes([b]), "big", signed=True) for b in raw]
            accounts = [keys[i] for i in ins["accounts"]]
            if len(accounts) < 3:
                raise lib.CheckerError(
                    f"the verify_signatures instruction in {tx_signature} names "
                    f"only {len(accounts)} accounts; it should name at least 3.")
            signature_set = accounts[2]

    if slots is None:
        raise lib.CheckerError(
            f"transaction {tx_signature} contains no verify_signatures "
            f"instruction (tag 7) for {program_id}.")
    if precompile_count is None:
        raise lib.CheckerError(
            f"transaction {tx_signature} verifies guardian signatures without "
            f"invoking {SECP256K1_PROGRAM}. That should not be possible; "
            "refusing to report a signature count from it.")

    signed = [i for i, v in enumerate(slots) if v >= 0]
    if len(signed) != precompile_count:
        raise lib.CheckerError(
            f"{tx_signature}: the core contract records {len(signed)} guardian "
            f"signatures but the secp256k1 precompile verified "
            f"{precompile_count}. The two readings disagree; no count is "
            "reported from this transaction.")

    return {
        "tx": tx_signature,
        "slots": len(slots),
        "signed": signed,
        "count": len(signed),
        "precompile_count": precompile_count,
        "signature_set": signature_set,
        "block_time": tx.get("blockTime"),
    }


def sample_signature_sets(program_id: str, want: int = 12, scan: int = 400,
                          url=None) -> list:
    """How many guardians signed the attestations this contract actually took.

    Walks recent transactions that touched the Core Contract, keeps the ones
    that also invoked the secp256k1 precompile — those are signature
    verifications — and reads back the signature-set account each one wrote.

    Direction of error: if this misses signatures or transactions, the smallest
    count it reports can only be *too low*. So an observed minimum of k is safe
    evidence that the contract accepts attestations at k, and an observed
    minimum below the claimed threshold would need a second look before it
    became a verdict.
    """
    signatures = lib.rpc("getSignaturesForAddress",
                         [program_id, {"limit": scan}], url=url)
    if not signatures:
        raise lib.CheckerError(
            f"no recent transactions found for {program_id}; cannot sample "
            "signature counts.")

    # Fetched in small chunks, stopping the moment there are enough candidates.
    # The free public endpoint rate-limits getTransaction hard, and asking it
    # for four hundred transactions at once earns a 429 and no verdict at all.
    candidates = []
    for start in range(0, len(signatures), 25):
        chunk = signatures[start:start + 25]
        params = [[s["signature"],
                   {"encoding": "json", "maxSupportedTransactionVersion": 0}]
                  for s in chunk]
        transactions = lib.rpc_batch("getTransaction", params, url=url)

        for meta, tx in zip(chunk, transactions):
            if tx is None or meta.get("err"):
                continue
            message = tx["transaction"]["message"]
            keys = message["accountKeys"]
            if SECP256K1_PROGRAM not in keys:
                continue
            for ins in message["instructions"]:
                if keys[ins["programIdIndex"]] != program_id:
                    continue
                # verify_signatures takes the signature set as its third account.
                accounts = [keys[i] for i in ins["accounts"]]
                if len(accounts) < 3:
                    continue
                candidates.append((meta["signature"], accounts[2]))
        if len(candidates) >= want * 3:
            break

    seen, results = set(), []
    for tx_signature, address in candidates:
        if address in seen:
            continue
        seen.add(address)
        try:
            account = lib.get_account(address, url=url)
        except lib.CheckerError:
            continue  # closed after use; its rent was reclaimed
        if account["owner"] != program_id:
            continue
        try:
            decoded = decode_signature_set(account["data"])
        except lib.CheckerError:
            continue  # some other account of this program, not a signature set
        decoded["address"] = address
        decoded["tx"] = tx_signature
        results.append(decoded)
        if len(results) >= want:
            break
    return results


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


def check(program_id=CORE_BRIDGE_MAINNET, set_index=None, expect_keys=None,
          expect_in_force=False, expect_quorum=None, history=False,
          check_upgrade_authority=False, sample=12, scan=400,
          verify_txs=None, url=None, out_path=None) -> int:
    checks = lib.Checks()
    findings = {"program": program_id, "checked_at": lib.utc_now()}

    lib.banner("Wormhole guardian set", url=url)

    config_address = bridge_config_address(program_id)
    config_account = lib.get_account(config_address, url=url)
    if config_account["owner"] != program_id:
        raise lib.CheckerError(
            f"the config account derived for {program_id} is owned by "
            f"{config_account['owner']}. This is not a Wormhole Core Contract.")
    config = decode_bridge_config(config_account["data"])
    findings["config"] = dict(config, address=config_address)

    print(f"  core contract        {program_id}")
    print(f"  config account       {config_address}  (PDA [\"Bridge\"])")
    print(f"  guardian set in force  index {config['guardian_set_index']}")
    print(f"  outgoing-set grace   {config['guardian_set_expiration_time']} seconds")
    print(f"  message fee          {config['fee']} lamports")

    current_index = config["guardian_set_index"]
    target_index = current_index if set_index is None else set_index
    gset = read_guardian_set(program_id, target_index, url=url)
    findings["guardian_set"] = gset

    print(f"\n  guardian set {target_index}")
    print(f"    account            {gset['address']}")
    print(f"    keys               {gset['count']} ({gset['distinct']} distinct)")
    print(f"    created            {fmt_time(gset['creation_time'])}")
    print(f"    expires            {fmt_time(gset['expiration_time'])}")
    for i, key in enumerate(gset["keys"]):
        print(f"      [{i:2d}] {key}")

    if expect_keys is not None:
        checks.expect(f"guardian set {target_index} holds {expect_keys} keys",
                      gset["count"], expect_keys)
    checks.expect(f"guardian set {target_index}'s keys are all distinct",
                  gset["distinct"], gset["count"])

    if expect_in_force:
        # "In force" is two facts, and both are asserted, because either one
        # alone can be true of a set that cannot actually be used.
        checks.expect(
            "the set checked is the one the config account names as current",
            target_index, current_index)
        checks.expect_true(
            f"guardian set {target_index} has not expired",
            gset["expiration_time"] == 0,
            f"expiration_time = {fmt_time(gset['expiration_time'])}; the "
            "current set carries 0, which is why 0 reads as no expiry")

    if history:
        sets = walk_history(program_id, url=url)
        findings["history"] = [
            {k: v for k, v in s.items() if k != "keys"} for s in sets]
        print(f"\n  guardian set history — {len(sets)} sets found")
        never_expire = []
        for s in sets:
            state = "CURRENT" if s["index"] == current_index else (
                "no expiry" if s["expiration_time"] == 0 else "expired")
            if s["expiration_time"] == 0 and s["index"] != current_index:
                never_expire.append(s["index"])
            print(f"    index {s['index']}: {s['count']:2d} keys, "
                  f"created {fmt_time(s['creation_time'])}, "
                  f"expires {fmt_time(s['expiration_time'])}  [{state}]")
        findings["superseded_sets_without_expiry"] = never_expire
        if never_expire:
            print(f"\n    NOTE: superseded set(s) {never_expire} carry "
                  "expiration_time = 0, the same value the current set uses "
                  "to mean 'no expiry'.")

    if check_upgrade_authority:
        expected_pda = upgrade_authority_pda(program_id)
        authority = spl_mint.program_upgrade_authority(program_id, url=url)
        found = authority.get("upgradeAuthority")
        findings["upgrade_authority"] = {"found": found,
                                         "self_governed_pda": expected_pda}
        print(f"\n  program upgrade authority  {found}")
        print(f"  PDA [\"upgrade\"] of itself   {expected_pda}")
        checks.expect(
            "the core contract can be upgraded only by itself "
            "(authority == its own PDA [\"upgrade\"], so no key can sign)",
            found, expected_pda)

    if verify_txs:
        # The pinned form: named transactions, which never change, rather than
        # signature-set accounts, which get closed to reclaim rent.
        verifications = [read_verification(program_id, s, url=url)
                         for s in verify_txs]
        findings["verifications"] = verifications
        sets_named = set(v["signature_set"] for v in verifications)
        union = sorted(set().union(*(set(v["signed"]) for v in verifications)))
        print(f"\n  guardian signatures verified across "
              f"{len(verifications)} transaction(s)")
        for v in verifications:
            print(f"    {v['count']:2d} of {v['slots']}  guardians "
                  f"{v['signed']}")
            print(f"        tx {v['tx']}")
            print(f"        secp256k1 precompile verified "
                  f"{v['precompile_count']} signature(s) — agrees")
        print(f"    accumulated into signature set "
              f"{', '.join(sorted(sets_named))}")
        print(f"    DISTINCT guardians that signed: {len(union)} — {union}")
        findings["distinct_signers"] = union

        checks.expect_true(
            "all the transactions given accumulate into ONE signature set "
            "(otherwise their counts cannot be added together)",
            len(sets_named) == 1, f"signature sets named: {sorted(sets_named)}")
        checks.expect_true(
            "no guardian's signature is counted twice across the transactions",
            sum(v["count"] for v in verifications) == len(union),
            f"{sum(v['count'] for v in verifications)} signatures, "
            f"{len(union)} distinct guardians")
        checks.expect_true(
            "every signature belongs to a guardian slot that exists in the set",
            all(i < gset["count"] for i in union),
            f"highest slot used: {max(union) if union else 'none'}, "
            f"set holds {gset['count']} keys")
        if expect_quorum is not None:
            checks.expect(
                f"{expect_quorum} distinct guardians signed this attestation",
                len(union), expect_quorum)

    elif expect_quorum is not None:
        observed = sample_signature_sets(program_id, want=sample, scan=scan,
                                         url=url)
        if not observed:
            checks.blocked(
                f"at least {expect_quorum} signatures on every accepted "
                "attestation",
                "no signature-set account could be read from the recent "
                "transactions sampled. Signature sets are often closed to "
                "reclaim rent; widen --scan or try again later.")
        else:
            counts = [o["signed"] for o in observed]
            findings["signature_sets"] = observed
            print(f"\n  signature counts on {len(observed)} accepted "
                  f"attestations")
            for o in observed:
                print(f"    {o['signed']:2d} of {o['slots']}  set "
                      f"{o['guardian_set_index']}  {o['flags']}  {o['address']}")
            print(f"    minimum observed: {min(counts)}   "
                  f"maximum observed: {max(counts)}")
            checks.expect(
                f"the fewest signatures on any attestation sampled is "
                f"{expect_quorum}",
                min(counts), expect_quorum)
            checks.expect_true(
                "every attestation sampled was verified against the guardian "
                "set checked",
                all(o["guardian_set_index"] == target_index for o in observed),
                f"indices seen: {sorted(set(o['guardian_set_index'] for o in observed))}")

    checks.print_report()
    print("""
WHAT THIS CANNOT TELL YOU
  * Nothing here names a guardian. The contract stores 20-byte addresses and
    no identity of any kind. A key set is not a list of companies.
  * The threshold is counted, not proved. Every accepted attestation sampled
    carried the same number of signatures, and no accepted attestation carried
    fewer — but a contract only writes down what it accepted, so on-chain
    evidence bounds the requirement from above and never from below.""")

    findings["checks"] = checks.rows
    if out_path:
        with open(out_path, "w") as handle:
            json.dump(findings, handle, indent=2, sort_keys=True)
        print(f"\n  findings written to {out_path}")

    return checks.exit_code()


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------


def self_test(url=None) -> int:
    """Controls, including ones designed to fail.

    A checker that cannot fail proves nothing, so roughly half of these feed it
    input that is wrong on purpose and require it to say so.
    """
    results = []

    def record(name, ok, detail, blocked=False):
        results.append((name, ok, detail, blocked))
        tag = "SKIP" if blocked else ("ok" if ok else "FAIL")
        print(f"  [{tag:>4}] {name}")
        if detail:
            print(f"         {detail}")

    print("guardian_set.py self-test\n")

    # --- derivation, offline -------------------------------------------------
    got = bridge_config_address(CORE_BRIDGE_MAINNET)
    record("PDA [\"Bridge\"] derives the known config account",
           got == "2yVjuQwpsvdsrywzsJJVs9Ueh4zayyo5DYJbBNc3DDpn", got)

    got = guardian_set_address(CORE_BRIDGE_MAINNET, 0)
    record("PDA [\"GuardianSet\", 0] derives the known set-0 account",
           got == "DS7qfSAgYsonPpKoAjcGhX9VFjXdGkiHjEDkTidf8H2P", got)

    got = guardian_set_address(CORE_BRIDGE_MAINNET, 7)
    record("PDA [\"GuardianSet\", 7] derives the known set-7 account",
           got == "6YLGQQEweF82hbPSWCSeJqifWyT8Pm4QXa3mWSLwjYSh", got)

    # NEGATIVE: little-endian instead of big-endian must not agree.
    little, _ = lib.find_program_address(
        [b"GuardianSet", struct.pack("<I", 7)],
        lib.parse_pubkey(CORE_BRIDGE_MAINNET))
    record("little-endian index derives a DIFFERENT address (byte order matters)",
           lib.b58encode(little) != guardian_set_address(CORE_BRIDGE_MAINNET, 7),
           lib.b58encode(little))

    got = upgrade_authority_pda(CORE_BRIDGE_MAINNET)
    record("PDA [\"upgrade\"] derives the known upgrade authority",
           got == "2rCAC1VKz5YP1jZTHcVfWDhHMs2iEruUaATdeZe5Fjk5", got)

    # NEGATIVE: an index that is not a u32.
    try:
        guardian_set_address(CORE_BRIDGE_MAINNET, -1)
        record("a negative guardian set index is refused", False, "it was accepted")
    except lib.CheckerError as exc:
        record("a negative guardian set index is refused", True, str(exc)[:60])

    # --- decoding, offline ---------------------------------------------------
    raw = bytes.fromhex("07000000a220123602000000805101006400000000000000")
    cfg = decode_bridge_config(raw)
    record("bridge config decodes to index 7, 86400s grace, 100 lamport fee",
           cfg["guardian_set_index"] == 7
           and cfg["guardian_set_expiration_time"] == 86400
           and cfg["fee"] == 100, str(cfg))

    # NEGATIVE: a config account of the wrong length.
    try:
        decode_bridge_config(raw[:20])
        record("a short bridge config is refused", False, "it was accepted")
    except lib.CheckerError as exc:
        record("a short bridge config is refused", True, str(exc)[:60])

    def build_set(index, keys, creation=1000, expiry=0, tail=b""):
        out = struct.pack("<I", index) + struct.pack("<I", len(keys))
        for key in keys:
            out += key
        return out + struct.pack("<II", creation, expiry) + tail

    keys19 = [bytes([i]) * GUARDIAN_KEY_LEN for i in range(1, 20)]
    decoded = decode_guardian_set(build_set(7, keys19))
    record("a synthetic 19-key set decodes to 19 distinct keys",
           decoded["count"] == 19 and decoded["distinct"] == 19,
           f"count={decoded['count']} distinct={decoded['distinct']}")

    # NEGATIVE: a duplicate key must be visible, not silently counted twice.
    dup = keys19[:-1] + [keys19[0]]
    decoded = decode_guardian_set(build_set(7, dup))
    record("a set containing a duplicate key reports distinct < count",
           decoded["count"] == 19 and decoded["distinct"] == 18,
           f"count={decoded['count']} distinct={decoded['distinct']}")

    # NEGATIVE: truncated data must raise, not return a short key list.
    try:
        decode_guardian_set(build_set(7, keys19)[:-3])
        record("a truncated guardian set is refused", False, "it was accepted")
    except lib.CheckerError as exc:
        record("a truncated guardian set is refused", True, str(exc)[:60])

    # NEGATIVE: trailing bytes must raise.
    try:
        decode_guardian_set(build_set(7, keys19, tail=b"\x00\x00"))
        record("trailing bytes after a guardian set are refused", False,
               "it was accepted")
    except lib.CheckerError as exc:
        record("trailing bytes after a guardian set are refused", True,
               str(exc)[:60])

    # NEGATIVE: an absurd key count must raise before allocating anything.
    try:
        decode_guardian_set(struct.pack("<I", 0) + struct.pack("<I", 10 ** 6))
        record("an absurd key count is refused", False, "it was accepted")
    except lib.CheckerError as exc:
        record("an absurd key count is refused", True, str(exc)[:60])

    def build_sigset(flags, index=7):
        out = struct.pack("<I", len(flags)) + bytes(flags)
        return out + bytes(32) + struct.pack("<I", index)

    decoded = decode_signature_set(build_sigset([1] * 13 + [0] * 6))
    record("a signature set with 13 of 19 flags counts 13",
           decoded["signed"] == 13 and decoded["slots"] == 19,
           f"signed={decoded['signed']} slots={decoded['slots']}")

    # NEGATIVE: a byte that is not a bool means this is not a signature set.
    try:
        decode_signature_set(build_sigset([1] * 12 + [7] + [0] * 6))
        record("a non-boolean signature flag is refused", False, "it was accepted")
    except lib.CheckerError as exc:
        record("a non-boolean signature flag is refused", True, str(exc)[:60])

    # NEGATIVE: a guardian set must not decode as a signature set.
    try:
        decode_signature_set(build_set(7, keys19))
        record("a guardian set does not decode as a signature set", False,
               "it was accepted")
    except lib.CheckerError as exc:
        record("a guardian set does not decode as a signature set", True,
               str(exc)[:60])

    record("expiration_time 0 formats as 'no expiry', not as 1970",
           fmt_time(0) == "0 (no expiry)", fmt_time(0))
    record("a real expiration_time formats as its UTC instant",
           fmt_time(1651502874) == "2022-05-02T14:47:54Z", fmt_time(1651502874))

    # --- against the chain ---------------------------------------------------
    try:
        gset = read_guardian_set(CORE_BRIDGE_MAINNET, 7, url=url)
        record("mainnet guardian set 7 has 19 distinct keys",
               gset["count"] == 19 and gset["distinct"] == 19,
               f"count={gset['count']} distinct={gset['distinct']}")

        gset0 = read_guardian_set(CORE_BRIDGE_MAINNET, 0, url=url)
        record("mainnet guardian set 0 is the 1-key bootstrap set",
               gset0["count"] == 1, f"count={gset0['count']}")

        cfg = decode_bridge_config(
            lib.get_account(bridge_config_address(CORE_BRIDGE_MAINNET),
                            url=url)["data"])
        record("the config account names a set that exists and is unexpired",
               read_guardian_set(CORE_BRIDGE_MAINNET,
                                 cfg["guardian_set_index"],
                                 url=url)["expiration_time"] == 0,
               f"current index {cfg['guardian_set_index']}")

        # NEGATIVE: a real Solana program that is not a Wormhole core contract
        # must be refused, not decoded into a plausible-looking guardian set.
        try:
            check(program_id="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
                  url=url)
            record("a non-Wormhole program is refused", False,
                   "it produced a report")
        except lib.CheckerError as exc:
            record("a non-Wormhole program is refused", True, str(exc)[:70])

        # NEGATIVE: the wrong key count must exit 1, not 0.
        code = check(expect_keys=20, url=url)
        record("claiming 20 keys against a 19-key set exits 1", code == 1,
               f"exit {code}")

        # POSITIVE: the real claim must exit 0.
        code = check(expect_keys=19, expect_in_force=True, url=url)
        record("claiming 19 keys, in force, exits 0", code == 0, f"exit {code}")

        # The pinned pair below fills one signature set: 6 signatures then 7.
        try:
            verifications = [read_verification(CORE_BRIDGE_MAINNET, s, url=url)
                             for s in PINNED_VERIFICATION_TXS]
            counts = [v["count"] for v in verifications]
            union = set().union(*(set(v["signed"]) for v in verifications))
            record("the pinned verification pair reads 6 then 7 signatures",
                   counts == [6, 7], f"counts {counts}")
            record("those 13 signatures are 13 DIFFERENT guardians",
                   len(union) == 13, f"{sorted(union)}")
            record("both pinned transactions fill the same signature set",
                   len(set(v["signature_set"] for v in verifications)) == 1,
                   verifications[0]["signature_set"])

            # POSITIVE then NEGATIVE on the same immutable evidence.
            code = check(expect_quorum=13,
                         verify_txs=PINNED_VERIFICATION_TXS, url=url)
            record("claiming a quorum of 13 on the pinned pair exits 0",
                   code == 0, f"exit {code}")
            code = check(expect_quorum=14,
                         verify_txs=PINNED_VERIFICATION_TXS, url=url)
            record("claiming a quorum of 14 on the pinned pair exits 1",
                   code == 1, f"exit {code}")

            # NEGATIVE: one transaction of the pair is 7 signatures, not 13.
            # Counting half the evidence must not reach the quorum.
            code = check(expect_quorum=13,
                         verify_txs=[PINNED_VERIFICATION_TXS[1]], url=url)
            record("half the pair alone does not reach a quorum of 13",
                   code == 1, f"exit {code}")

            # NEGATIVE: a transaction that is not a verify_signatures call.
            try:
                read_verification(
                    CORE_BRIDGE_MAINNET,
                    "5bzihUBNVxKDuG2gSWp18huHK1xTgihETaTZ7BzNEnL9cdDoxHBZX9"
                    "Wt3nBnpvcpwZtpSAUGJf6kB6xL7JKxd2dm", url=url)
                record("a transaction with no verify_signatures is refused",
                       False, "it was accepted")
            except lib.CheckerError as exc:
                record("a transaction with no verify_signatures is refused",
                       True, str(exc)[:70])
        except lib.CheckerError as exc:
            record("pinned verification controls", True,
                   f"skipped, endpoint lacks the history: {str(exc)[:60]}",
                   blocked=True)

    except lib.CheckerError as exc:
        record("chain-facing controls", True,
               f"skipped, endpoint unavailable: {str(exc)[:70]}", blocked=True)

    real = [r for r in results if not r[3]]
    passed = sum(1 for r in real if r[1])
    skipped = sum(1 for r in results if r[3])
    negatives = sum(1 for r in real
                    if "refused" in r[0] or "exits 1" in r[0]
                    or "DIFFERENT" in r[0] or "duplicate" in r[0]
                    or "does not decode" in r[0] or "exits 1" in r[0]
                    or "does not reach" in r[0])
    print(f"\n  {passed}/{len(real)} controls passed "
          f"({negatives} of them negative), {skipped} skipped")
    return 0 if passed == len(real) else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check a Wormhole guardian set on Solana from raw account "
                    "bytes.")
    parser.add_argument("--program", default=CORE_BRIDGE_MAINNET,
                        help="the Wormhole Core Contract (default: Solana mainnet)")
    parser.add_argument("--set", type=int, default=None, metavar="N",
                        help="check this guardian set index (default: the one in force)")
    parser.add_argument("--expect-keys", type=int, default=None, metavar="N",
                        help="assert the set holds exactly N keys")
    parser.add_argument("--expect-in-force", action="store_true",
                        help="assert the set checked is the current one and has not expired")
    parser.add_argument("--expect-quorum", type=int, default=None, metavar="K",
                        help="assert the fewest signatures on any sampled attestation is K")
    parser.add_argument("--history", action="store_true",
                        help="walk every guardian set from index 0")
    parser.add_argument("--upgrade-authority", action="store_true",
                        help="assert the contract is upgradeable only by itself")
    parser.add_argument("--sample", type=int, default=12, metavar="N",
                        help="how many signature sets to read (default 12)")
    parser.add_argument("--scan", type=int, default=400, metavar="N",
                        help="how many recent transactions to look through (default 400)")
    parser.add_argument("--verify-tx", metavar="SIG,SIG,...",
                        help="count guardian signatures from these named "
                             "verify_signatures transactions instead of "
                             "sampling; immutable, so safe to publish")
    parser.add_argument("--rpc", metavar="URL", help="a Solana RPC endpoint")
    parser.add_argument("--json", metavar="PATH", help="write the findings here")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    url = args.rpc or None
    try:
        if args.self_test:
            return self_test(url=url)
        return check(program_id=args.program, set_index=args.set,
                     expect_keys=args.expect_keys,
                     expect_in_force=args.expect_in_force,
                     expect_quorum=args.expect_quorum,
                     history=args.history,
                     check_upgrade_authority=args.upgrade_authority,
                     sample=args.sample, scan=args.scan,
                     verify_txs=[s.strip() for s in args.verify_tx.split(",")
                                 if s.strip()] if args.verify_tx else None,
                     url=url, out_path=args.json)
    except lib.CheckerError as exc:
        print(f"\nCOULD NOT CHECK: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 2


if __name__ == "__main__":
    sys.exit(main())
