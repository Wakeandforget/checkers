#!/usr/bin/env python3
"""
lp_burn.py — did the liquidity-pool tokens actually get burnt?

CLAIM CLASS: "the LP tokens were burnt", "liquidity is locked", "we can't pull
the rug" — for pools created by pump.fun's migration to PumpSwap. Reads the
migration transaction itself and asserts that every LP token minted in it was
burnt in it, rather than inferring a burn from today's zero balance. Also
reports how much LP is outstanding right now from later deposits, which is the
part the popular restatement of the claim gets wrong.

SECOND CLAIM CLASS: "this pool is a graduated pump.fun coin". An index of 0
does not establish that; the checker re-derives the migration authority from
the coin's own mint and fails if the pool's creator is anyone else.

RUN: python3 checkers/lp_burn.py <POOL_ADDRESS> --expect-burned <N>

The claim class in full
-----------------------
"The LP tokens are burnt", "liquidity is locked", "we can't pull the rug".
This is one of the most repeated safety claims in the retail Solana market and
one of the least checked. Burning the LP tokens received when a pool is seeded
means whoever seeded it cannot call `withdraw` to take the liquidity back out.

This checker was written for pump.fun's version of that claim, in its own
public docs (`pump-public-docs/docs/PUMP_PROGRAM_README.md`, lines 3-5):

    "When the coin hits a certain market cap the liquidity from the bonding
     curve is migrated to PumpSwap (an AMM on Solana). The LP tokens received
     from the PumpSwap pool are then burnt."

What it actually proves
-----------------------
For a PumpSwap pool created by the Pump program's `migrate` instruction, it
finds the migration transaction itself and asserts that, inside that one
transaction:

  * LP tokens were minted (amount > 0) to the migration authority, and
  * exactly that many LP tokens were burnt, and
  * no LP token balance survived the transaction, and
  * the migration authority's LP token account was closed.

Reading the *transaction* rather than today's balances matters. Today's LP
supply being zero is consistent with "burnt at migration" and also with
"minted, held for a month, and burnt last Tuesday". The transaction settles it,
and unlike an account balance a confirmed transaction never changes, so every
assertion here still holds in a year.

What it deliberately does NOT prove
-----------------------------------
That the pool's liquidity is locked. Burning the migration LP removes the
*migrator's* ability to withdraw. It does not stop anyone else depositing later
and receiving fresh, withdrawable LP tokens. This checker reports that
outstanding amount as an observation, never as a pass or a fail, because it is
a live number that changes with every deposit.

Standard library only. No credentials. Read-only.
"""

import argparse
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _lib as lib
from _lib import CheckerError, Checks, b58decode, b58encode, find_program_address
from spl_mint import decode_mint

# ---------------------------------------------------------------------------
# The programs involved. All three addresses are published by pump.fun itself.
# ---------------------------------------------------------------------------

PUMP_PROGRAM = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
PUMPSWAP_PROGRAM = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
ATA_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"

# Anchor writes an 8-byte tag at the front of every account so a program can
# tell its own account types apart. sha256("account:Pool")[:8].
POOL_DISCRIMINATOR = lib.anchor_discriminator("Pool")

# ---------------------------------------------------------------------------
# The Pool account layout
# ---------------------------------------------------------------------------
# Taken from pump.fun's PUMP_SWAP_README.md, which prints a worked example of
# a decoded Pool account. Byte offsets, counting from the start of the account
# data including the 8-byte Anchor tag:
#
#     0   8  discriminator
#     8   1  pool_bump              u8
#     9   2  index                  u16 little-endian
#    11  32  creator                pubkey
#    43  32  base_mint              pubkey
#    75  32  quote_mint             pubkey
#   107  32  lp_mint                pubkey
#   139  32  pool_base_token_account
#   171  32  pool_quote_token_account
#   203   8  lp_supply              u64 little-endian
#   211  32  coin_creator           pubkey        (later accounts only)
#   243   1  is_mayhem_mode         bool          (later accounts only)
#   244   1  is_cashback_coin       bool          (later accounts only)
#   245  16  virtual_quote_reserves i128          (later accounts only)
#
# Pool accounts on mainnet exist at seven different sizes — 211, 243, 244,
# 245, 261, 300 and 301 bytes — because fields were appended over time and
# `extend_account` grows old accounts in place. Everything this checker needs
# lives in the first 211 bytes, which every one of those sizes contains, so
# POOL_MIN_LEN is 211 and the tail is decoded only when it is present.
POOL_MIN_LEN = 211


def decode_pool(data: bytes) -> dict:
    """Turn raw Pool account bytes into named fields. Raises if they are not
    Pool account bytes — never guesses."""
    if len(data) < POOL_MIN_LEN:
        raise CheckerError(
            f"account is {len(data)} bytes; a PumpSwap Pool needs at least "
            f"{POOL_MIN_LEN}. This is not a Pool account.")
    if data[:8] != POOL_DISCRIMINATOR:
        raise CheckerError(
            f"account tag is {data[:8].hex()}, expected "
            f"{POOL_DISCRIMINATOR.hex()} (sha256('account:Pool')[:8]). "
            "This is not a PumpSwap Pool account.")
    out = {
        "poolBump": data[8],
        "index": int.from_bytes(data[9:11], "little"),
        "creator": b58encode(data[11:43]),
        "baseMint": b58encode(data[43:75]),
        "quoteMint": b58encode(data[75:107]),
        "lpMint": b58encode(data[107:139]),
        "poolBaseTokenAccount": b58encode(data[139:171]),
        "poolQuoteTokenAccount": b58encode(data[171:203]),
        "lpSupply": int.from_bytes(data[203:211], "little"),
        "accountLen": len(data),
    }
    # Fields that only exist on accounts long enough to hold them. Absent is
    # recorded as absent, not as a zero, because those are different facts.
    out["coinCreator"] = b58encode(data[211:243]) if len(data) >= 243 else None
    out["isMayhemMode"] = bool(data[243]) if len(data) >= 244 else None
    out["isCashbackCoin"] = bool(data[244]) if len(data) >= 245 else None
    out["virtualQuoteReserves"] = (
        int.from_bytes(data[245:261], "little", signed=True)
        if len(data) >= 261 else None)
    return out


# ---------------------------------------------------------------------------
# The three addresses you have to derive to check this claim
# ---------------------------------------------------------------------------


def lp_mint_pda(pool: str) -> str:
    """The LP mint a PumpSwap pool must use: PDA of ["pool_lp_mint", pool].

    The Pool account also stores the LP mint. Deriving it independently and
    comparing is what stops someone pointing us at a pool whose stored lp_mint
    is a decoy mint with a convenient zero supply.
    """
    addr, _ = find_program_address([b"pool_lp_mint", b58decode(pool)],
                                   b58decode(PUMPSWAP_PROGRAM))
    return b58encode(addr)


def migration_authority(base_mint: str) -> str:
    """The Pump program PDA that performs a migration: ["pool-authority", mint].

    This is the account that receives the LP tokens at migration, and it is
    also the `creator` recorded in a genuinely-migrated pool. It is a program
    derived address, so no private key for it exists.
    """
    addr, _ = find_program_address([b"pool-authority", b58decode(base_mint)],
                                   b58decode(PUMP_PROGRAM))
    return b58encode(addr)


def associated_token_address(owner: str, token_program: str, mint: str) -> str:
    """The standard ATA: PDA of [owner, token_program, mint]."""
    addr, _ = find_program_address(
        [b58decode(owner), b58decode(token_program), b58decode(mint)],
        b58decode(ATA_PROGRAM))
    return b58encode(addr)


# ---------------------------------------------------------------------------
# Reading the migration transaction
# ---------------------------------------------------------------------------


def _amount(info: dict) -> int:
    """Pull the amount out of a parsed SPL-token instruction.

    mintTo/burn carry "amount"; mintToChecked/burnChecked carry a nested
    "tokenAmount". Missing both is an error, never a zero.
    """
    if "amount" in info:
        return int(info["amount"])
    if "tokenAmount" in info and "amount" in info["tokenAmount"]:
        return int(info["tokenAmount"]["amount"])
    raise CheckerError(f"parsed token instruction has no amount: {info!r}")


def migration_transaction(lp_mint: str, authority_ata: str, url=None) -> dict:
    """Find and decode the transaction that created the pool's LP tokens.

    The migration authority's LP token account is created, funded, emptied and
    closed inside the migration transaction and is never used again, so its
    signature history is tiny and its oldest successful entry IS the migration.
    That is why we look it up through the ATA rather than through the pool,
    whose history is every swap ever made.
    """
    sigs = lib.rpc("getSignaturesForAddress",
                   [authority_ata, {"limit": 1000}], url=url)
    if not isinstance(sigs, list):
        raise CheckerError("getSignaturesForAddress did not return a list")
    successful = [s for s in sigs if not s.get("err")]
    if not successful:
        raise CheckerError(
            f"no successful transaction found on {authority_ata}, the "
            f"migration authority's LP token account. Either this pool was not "
            f"created by the Pump migrate instruction, or this RPC endpoint "
            f"does not serve history that far back (it returned "
            f"{len(sigs)} signatures, {len(sigs) - len(successful)} of them "
            f"failed). Try an endpoint with full archive history.")
    if len(successful) > 1:
        # Not fatal, but the reader should know we picked the oldest.
        pass
    sig = successful[-1]["signature"]

    tx = lib.rpc("getTransaction",
                 [sig, {"encoding": "jsonParsed",
                        "maxSupportedTransactionVersion": 0}], url=url)
    if not tx:
        raise CheckerError(f"transaction {sig} could not be fetched")
    meta = tx.get("meta") or {}
    if meta.get("err"):
        raise CheckerError(f"transaction {sig} failed on chain: {meta['err']}")

    found = {"minted": 0, "burned": 0, "recipients": set(),
             "ata_closed": False, "mint_initialized": False}

    def walk(instructions):
        for ix in instructions:
            parsed = ix.get("parsed")
            if not isinstance(parsed, dict):
                continue
            kind = parsed.get("type")
            info = parsed.get("info") or {}
            if kind in ("mintTo", "mintToChecked") and info.get("mint") == lp_mint:
                found["minted"] += _amount(info)
                found["recipients"].add(info.get("account"))
            elif kind in ("burn", "burnChecked") and info.get("mint") == lp_mint:
                found["burned"] += _amount(info)
            elif kind == "closeAccount" and info.get("account") == authority_ata:
                found["ata_closed"] = True
            elif (kind in ("initializeMint", "initializeMint2")
                  and info.get("mint") == lp_mint):
                found["mint_initialized"] = True

    walk(tx["transaction"]["message"]["instructions"])
    for inner in meta.get("innerInstructions", []):
        walk(inner["instructions"])

    # postTokenBalances is the runtime's own record of every token balance at
    # the end of the transaction. If any LP balance is left standing here, LP
    # tokens survived the migration whatever the instruction list says.
    leftovers = [
        {"account_index": b.get("accountIndex"), "owner": b.get("owner"),
         "amount": b["uiTokenAmount"]["amount"]}
        for b in meta.get("postTokenBalances", [])
        if b.get("mint") == lp_mint and int(b["uiTokenAmount"]["amount"]) != 0
    ]

    return {
        "signature": sig,
        "slot": tx.get("slot"),
        "blockTime": tx.get("blockTime"),
        "minted": found["minted"],
        "burned": found["burned"],
        "lpRecipients": sorted(x for x in found["recipients"] if x),
        "authorityAtaClosed": found["ata_closed"],
        "lpMintInitializedHere": found["mint_initialized"],
        "nonZeroLpBalancesAfter": leftovers,
        "signatureCountOnAta": len(sigs),
    }


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


def check(pool_address, expect_burned=None, require_canonical=True,
          skip_transaction=False, url=None):
    """Check one PumpSwap pool. Returns (Checks, facts)."""
    checks = Checks()
    facts = {"pool": pool_address, "checkedAt": lib.utc_now()}

    acct = lib.get_account(pool_address, url=url)
    facts["poolOwner"] = acct["owner"]
    if acct["owner"] != PUMPSWAP_PROGRAM:
        raise CheckerError(
            f"account {pool_address} is owned by {acct['owner']}, not the "
            f"PumpSwap program {PUMPSWAP_PROGRAM}. This is not a PumpSwap pool.")

    pool = decode_pool(acct["data"])
    facts["pool_decoded"] = pool

    print(f"  pool account       {pool_address}  ({pool['accountLen']} bytes)")
    print(f"  index              {pool['index']}")
    print(f"  creator            {pool['creator']}")
    print(f"  base mint          {pool['baseMint']}")
    print(f"  quote mint         {pool['quoteMint']}")
    print(f"  lp mint            {pool['lpMint']}")
    print(f"  Pool::lp_supply    {pool['lpSupply']:,}")

    # --- 1. the LP mint is the one the program is forced to use ------------
    derived_lp = lp_mint_pda(pool_address)
    facts["lpMintDerived"] = derived_lp
    checks.expect("Pool::lp_mint equals PDA['pool_lp_mint', pool]",
                  pool["lpMint"], derived_lp)

    # --- 2. this pool really was created by the Pump migrate instruction ---
    authority = migration_authority(pool["baseMint"])
    facts["migrationAuthority"] = authority
    canonical = pool["creator"] == authority
    facts["canonical"] = canonical
    if require_canonical:
        checks.expect(
            "Pool::creator equals PDA['pool-authority', base_mint] "
            "(i.e. this pool was created by Pump's migrate instruction)",
            pool["creator"], authority)
    else:
        checks.observe("created by Pump migrate", canonical)
    if not canonical:
        print(f"\n  NOTE: creator {pool['creator']} is NOT the Pump migration")
        print(f"  authority {authority}. An index of 0 does not by itself mean")
        print( "  a pool was created by a pump.fun migration — anyone may create")
        print( "  an index-0 pool for a mint pair they are the creator of.")

    # --- 3. LP tokens existed at all ---------------------------------------
    checks.expect_true("Pool::lp_supply is greater than zero (LP tokens were "
                       "issued for this pool at all)",
                       pool["lpSupply"] > 0, f"lp_supply = {pool['lpSupply']:,}")

    # --- 4. today's live LP supply: an observation, never an assertion -----
    mint_acct = lib.get_account(pool["lpMint"], url=url)
    mint = decode_mint(mint_acct["data"])
    facts["lpMintDecoded"] = {
        "owner": mint_acct["owner"],
        "supplyBaseUnits": mint["supplyBaseUnits"],
        "decimals": mint["decimals"],
        "mintAuthority": mint["mintAuthority"],
        "freezeAuthority": mint["freezeAuthority"],
    }
    checks.expect("LP mint authority is the pool itself",
                  mint["mintAuthority"], pool_address)
    live = mint["supplyBaseUnits"]
    print(f"  live LP supply     {live:,}  (right now, {facts['checkedAt']})")
    checks.observe("live LP supply in base units (changes with every deposit "
                   "and withdrawal — reported, not asserted)", live)
    if pool["lpSupply"] > 0:
        pct = 100.0 * live / pool["lpSupply"]
        checks.observe("outstanding LP as a share of Pool::lp_supply",
                       f"{pct:.6f}%")
        if live > 0:
            print(f"\n  OUTSTANDING LIQUIDITY: {live:,} LP tokens exist right now")
            print(f"  ({pct:.6f}% of Pool::lp_supply). Whoever holds them can call")
            print( "  withdraw and take that share of the pool out. Burning the")
            print( "  migration LP does not stop later depositors doing this.")

    # --- 5. the transaction itself: did the migration burn what it minted? --
    # If the pool was not created by `migrate` there is no migration to read,
    # and hunting for one would turn a settled FALSE ("this is not a migrated
    # pool") into a vague "could not check". The failure is already recorded
    # above, so stop here and let it stand.
    if require_canonical and not canonical:
        print("\n  Not a migrated pool, so there is no migration transaction "
              "to read.\n  Pass --allow-non-migrated to inspect it anyway.")
        return checks, facts

    if skip_transaction:
        checks.blocked("migration transaction mint-and-burn",
                       "--skip-transaction was passed")
        return checks, facts

    token_program = mint_acct["owner"]
    ata = associated_token_address(authority, token_program, pool["lpMint"])
    facts["migrationAuthorityLpAta"] = ata
    print(f"  migration auth.    {authority}")
    print(f"  its LP token acct  {ata}")

    tx = migration_transaction(pool["lpMint"], ata, url=url)
    facts["migration"] = tx
    print(f"\n  migration tx       {tx['signature']}")
    print(f"  slot               {tx['slot']}")
    print(f"  LP minted          {tx['minted']:,}")
    print(f"  LP burnt           {tx['burned']:,}")

    checks.expect_true(
        "the migration transaction minted LP tokens (amount > 0)",
        tx["minted"] > 0, f"minted = {tx['minted']:,}")
    checks.expect("LP burnt in the migration transaction equals LP minted "
                  "in it", tx["burned"], tx["minted"])
    checks.expect_true(
        "no LP token balance survived the migration transaction",
        not tx["nonZeroLpBalancesAfter"],
        f"{len(tx['nonZeroLpBalancesAfter'])} non-zero LP balances in "
        f"postTokenBalances")
    checks.expect("the migration authority's LP token account was closed in "
                  "the same transaction", tx["authorityAtaClosed"], True)
    checks.observe("LP mint created in this same transaction",
                   tx["lpMintInitializedHere"])
    checks.observe("Pool::lp_supply minus LP minted at migration",
                   f"{pool['lpSupply'] - tx['minted']:,} base units "
                   "(100 = the permanently unminted minimum-liquidity offset; "
                   "anything above that is later deposits)")

    if expect_burned is not None:
        checks.expect("LP burnt at migration equals the expected amount",
                      tx["burned"], expect_burned)

    return checks, facts


# ---------------------------------------------------------------------------
# Survey: is the single pool above representative?
# ---------------------------------------------------------------------------


def survey(k=200, url=None, out_path=None):
    """Sample migrated pools deterministically and report outstanding LP.

    Selection rule, fixed before any result is seen:

      1. Fetch every PumpSwap Pool account with index == 0.
      2. Sort the addresses as base58 strings — an ordering nobody controls
         and which has nothing to do with the answer.
      3. Take every (N // K)-th, giving K pools spread across the whole set.
      4. Keep the ones whose creator is the Pump migration authority.

    Every pool selected is reported, including inconvenient ones. Needs
    getProgramAccounts, which many free endpoints refuse.
    """
    print("Enumerating every PumpSwap Pool account with index == 0.")
    print("This is a large call and takes ~20s on an endpoint that allows it.")
    slot = lib.rpc("getSlot", [], url=url)
    accounts = lib.rpc(
        "getProgramAccounts",
        [PUMPSWAP_PROGRAM,
         {"encoding": "base64", "dataSlice": {"offset": 0, "length": 0},
          "filters": [{"memcmp": {"offset": 0,
                                  "bytes": b58encode(POOL_DISCRIMINATOR)}},
                      {"memcmp": {"offset": 9, "bytes": "11"}}]}],
        url=url, timeout=300, attempts=1)
    keys = sorted(a["pubkey"] for a in accounts)
    total = len(keys)
    if total < k:
        raise CheckerError(f"only {total} pools found; cannot sample {k}")
    step = total // k
    sample = [keys[i * step] for i in range(k)]
    print(f"  index-0 pools on chain: {total:,}   (slot {slot})")
    print(f"  sampling every {step:,}-th, giving {len(sample)}")

    def multi(addresses, slc=None):
        opts = {"encoding": "base64"}
        if slc:
            opts["dataSlice"] = slc
        out = []
        for i in range(0, len(addresses), 100):
            got = lib.rpc("getMultipleAccounts",
                          [addresses[i:i + 100], opts], url=url)["value"]
            if len(got) != len(addresses[i:i + 100]):
                raise CheckerError("getMultipleAccounts returned the wrong count")
            out += got
        return out

    rows = []
    for addr, acc in zip(sample, multi(sample, {"offset": 11, "length": 200})):
        if acc is None:
            raise CheckerError(f"pool {addr} vanished between calls")
        d = base64.b64decode(acc["data"][0])
        row = {"pool": addr, "creator": b58encode(d[0:32]),
               "baseMint": b58encode(d[32:64]), "quoteMint": b58encode(d[64:96]),
               "lpMint": b58encode(d[96:128]),
               "lpSupply": int.from_bytes(d[192:200], "little")}
        row["migrationAuthority"] = migration_authority(row["baseMint"])
        row["canonical"] = row["creator"] == row["migrationAuthority"]
        rows.append(row)

    canonical = [r for r in rows if r["canonical"]]
    print(f"  of those, created by Pump's migrate instruction: {len(canonical)}")
    for row, acc in zip(canonical, multi([r["lpMint"] for r in canonical])):
        if acc is None:
            raise CheckerError(f"LP mint {row['lpMint']} does not exist")
        m = decode_mint(base64.b64decode(acc["data"][0]))
        row["liveSupply"] = m["supplyBaseUnits"]
        row["mintAuthority"] = m["mintAuthority"]
        row["lpMintPdaOk"] = lp_mint_pda(row["pool"]) == row["lpMint"]

    zero = [r for r in canonical if r["liveSupply"] == 0]
    outstanding = [r for r in canonical if r["liveSupply"] > 0]
    nothing_burnt = [r for r in canonical if r["liveSupply"] == r["lpSupply"]]

    print("")
    print(f"  migrated pools sampled ............ {len(canonical)}")
    print(f"    Pool::lp_supply > 0 ............. "
          f"{sum(1 for r in canonical if r['lpSupply'] > 0)}")
    print(f"    lp_mint is the correct PDA ...... "
          f"{sum(1 for r in canonical if r['lpMintPdaOk'])}")
    print(f"    mint authority is the pool ...... "
          f"{sum(1 for r in canonical if r['mintAuthority'] == r['pool'])}")
    print(f"    live LP supply == 0 ............. {len(zero)}")
    print(f"    live LP supply > 0 .............. {len(outstanding)}")
    print(f"    live LP supply == lp_supply ..... {len(nothing_burnt)}  "
          f"(would mean nothing was ever burnt)")
    for r in outstanding:
        print(f"      outstanding: {r['pool']}  base {r['baseMint']}  "
              f"{r['liveSupply']:,} of {r['lpSupply']:,} "
              f"({100.0 * r['liveSupply'] / r['lpSupply']:.6f}%)")

    result = {"slot": slot, "index0Total": total, "k": k, "step": step,
              "checkedAt": lib.utc_now(), "rows": rows}
    if out_path:
        Path(out_path).write_text(json.dumps(result, indent=1), encoding="utf-8")
        print(f"\n  wrote {out_path}")
    return result


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------
# A check that cannot fail proves nothing. Half of these controls are negative:
# known-bad input that MUST be rejected. If a negative control passes, this
# checker is broken and says so.
#
# Everything pinned here is immutable: PDA arithmetic, and one confirmed
# transaction. Nothing in this self-test depends on a live balance, so it will
# still be correct in a year.
# ---------------------------------------------------------------------------

# The pool pump.fun uses as the worked example in its own PUMP_SWAP_README.md.
DOCS_POOL = "GseMAnNDvntR5uFePZ51yZBXzNSn7GdFPkfHwfr6d77J"
DOCS_BASE_MINT = "7LSsEoJGhLeZzGvDofTdNg7M3JttxQqGWNLo6vWMpump"
DOCS_LP_MINT = "6dpnPD6UWDw5hbJEuPQwnCCMba1JYwHANKuL6GQ6otAH"
DOCS_AUTHORITY = "9XDYTfQKwW8sHPqnFdUreMmtmffmkHVPGTNV2e3LKxNW"
DOCS_LP_ATA = "4N8q6iVoPj1TzFgVgU4iMYEzxgSw6rsAX19qdnm2tcw6"
DOCS_MIGRATION_SIG = ("3xP4ZANkJexrT75PmWKEAA5bjhNnzJcK6JkV1pxwkHJZmMtt4"
                      "KpB9tj3aw9fK6N7wRCCPGakkzYzhB76TRLXPGHN")
DOCS_MIGRATION_AMOUNT = 4193388284700
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

# A real index-0 PumpSwap pool that was NOT created by a pump.fun migration.
# Its creator field is written once at creation and can never change.
NON_MIGRATED_POOL = "114XmiBstWqYVhSiH6qnU4jFCskFxP8t9iBqBLJPmaf"


def _synthetic_pool(lp_mint=b"\x02" * 32, lp_supply=1000, index=0,
                    discriminator=None, length=211) -> bytes:
    """Build Pool account bytes by hand, so the decoder can be tested with no
    network at all and with fields we choose."""
    out = bytearray(length)
    out[0:8] = discriminator if discriminator is not None else POOL_DISCRIMINATOR
    out[8] = 254
    out[9:11] = index.to_bytes(2, "little")
    out[11:43] = b"\x01" * 32    # creator
    out[43:75] = b"\x03" * 32    # base mint
    out[75:107] = b"\x04" * 32   # quote mint
    out[107:139] = lp_mint
    out[139:171] = b"\x05" * 32
    out[171:203] = b"\x06" * 32
    out[203:211] = lp_supply.to_bytes(8, "little")
    return bytes(out)


def self_test(url=None) -> int:
    lib.banner("lp_burn.py self-test", url)
    passed = failed = negatives = 0

    def control(name, fn, negative=False):
        nonlocal passed, failed, negatives
        kind = "NEGATIVE" if negative else "positive"
        if negative:
            negatives += 1
        try:
            fn()
        except AssertionError as exc:
            print(f"  [FAIL] ({kind}) {name}\n         {exc}")
            failed += 1
        except CheckerError as exc:
            print(f"  [FAIL] ({kind}) {name}\n         CheckerError: {exc}")
            failed += 1
        else:
            print(f"  [ ok ] ({kind}) {name}")
            passed += 1

    print("\nOFFLINE CONTROLS — no network, deterministic forever")
    print("-" * 70)

    def c1():
        p = decode_pool(_synthetic_pool())
        assert p["index"] == 0, p
        assert p["lpSupply"] == 1000, p
        assert p["lpMint"] == b58encode(b"\x02" * 32), p
        assert p["coinCreator"] is None, "211-byte pool has no coin_creator"
    control("a hand-built 211-byte Pool decodes to the fields we put in", c1)

    def c2():
        p = decode_pool(_synthetic_pool(length=300))
        assert p["coinCreator"] == b58encode(b"\x00" * 32), p
        assert p["virtualQuoteReserves"] == 0, p
    control("a 300-byte Pool also decodes the appended tail fields", c2)

    def c3():
        try:
            decode_pool(_synthetic_pool(discriminator=b"\x00" * 8))
        except CheckerError:
            return
        raise AssertionError("decoded an account with the wrong Anchor tag")
    control("an account with the wrong Anchor tag is REJECTED", c3, True)

    def c4():
        try:
            decode_pool(_synthetic_pool()[:200])
        except CheckerError:
            return
        raise AssertionError("decoded a 200-byte account as a Pool")
    control("a too-short account is REJECTED", c4, True)

    def c5():
        assert lp_mint_pda(DOCS_POOL) == DOCS_LP_MINT, lp_mint_pda(DOCS_POOL)
    control("PDA['pool_lp_mint', docs pool] re-derives the documented LP mint",
            c5)

    def c6():
        got = migration_authority(DOCS_BASE_MINT)
        assert got == DOCS_AUTHORITY, got
    control("PDA['pool-authority', docs base mint] re-derives the pool creator "
            "recorded on chain", c6)

    def c7():
        got = associated_token_address(DOCS_AUTHORITY, TOKEN_2022, DOCS_LP_MINT)
        assert got == DOCS_LP_ATA, got
    control("the migration authority's LP token account re-derives as an ATA",
            c7)

    def c8():
        # One wrong byte in the seed must give a completely different address.
        wrong = migration_authority(DOCS_LP_MINT)
        assert wrong != DOCS_AUTHORITY, "different seed gave the same PDA"
    control("a different seed does NOT produce the same authority PDA",
            c8, True)

    def c9():
        try:
            _amount({"no": "amount"})
        except CheckerError:
            return
        raise AssertionError("_amount invented a number")
    control("a parsed instruction with no amount raises rather than "
            "returning 0", c9, True)

    print("\nONLINE CONTROLS — need an RPC endpoint")
    print("-" * 70)
    try:
        genesis = lib.rpc("getGenesisHash", [], url=url)
    except CheckerError as exc:
        print(f"  [SKIP] no usable RPC endpoint: {exc}")
        print(f"\n{passed} passed, {failed} failed, online controls skipped.")
        return 2 if failed == 0 else 1

    def c10():
        assert genesis == "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d", genesis
    control("the endpoint is Solana mainnet-beta and not a devnet fork", c10)

    def c11():
        tx = migration_transaction(DOCS_LP_MINT, DOCS_LP_ATA, url=url)
        assert tx["signature"] == DOCS_MIGRATION_SIG, tx["signature"]
        assert tx["minted"] == DOCS_MIGRATION_AMOUNT, tx["minted"]
        assert tx["burned"] == DOCS_MIGRATION_AMOUNT, tx["burned"]
        assert tx["nonZeroLpBalancesAfter"] == [], tx["nonZeroLpBalancesAfter"]
        assert tx["authorityAtaClosed"] is True, tx
    control("the docs pool's migration tx minted and burnt exactly "
            f"{DOCS_MIGRATION_AMOUNT:,} LP (a confirmed transaction, so this "
            "answer can never change)", c11)

    def c12():
        checks, _ = check(DOCS_POOL, expect_burned=DOCS_MIGRATION_AMOUNT + 1,
                          url=url)
        assert checks.exit_code() == 1, \
            f"expected exit 1 for a wrong burn amount, got {checks.exit_code()}"
    control("asserting a burn amount one unit too high gives exit 1", c12, True)

    def c13():
        checks, facts = check(NON_MIGRATED_POOL, skip_transaction=True, url=url)
        assert facts["canonical"] is False, facts["creator"]
        assert checks.exit_code() == 1, \
            f"a non-migrated index-0 pool should fail, got {checks.exit_code()}"
    control("a real index-0 pool that pump.fun did NOT migrate is rejected, "
            "not waved through", c13, True)

    def c14():
        try:
            check(PUMPSWAP_PROGRAM, url=url)
        except CheckerError:
            return
        raise AssertionError("checked the program account as if it were a pool")
    control("pointing the checker at the program itself raises rather than "
            "returning a clean result", c14, True)

    def c15():
        checks, facts = check(DOCS_POOL, url=url)
        assert checks.exit_code() == 0, checks.rows
        live = facts["lpMintDecoded"]["supplyBaseUnits"]
        # Not an assertion about the number: only that the field is real and
        # this checker would notice if LP were outstanding.
        assert isinstance(live, int) and live >= 0, live
    control("the full check of the docs pool passes end to end", c15)

    print("")
    print("-" * 70)
    print(f"{passed} controls passed, {failed} failed, "
          f"{negatives} of them negative (known-bad input that must be "
          f"rejected).")
    if failed:
        print("SELF-TEST FAILED. Do not trust this checker's verdicts.")
        return 1
    print("Self-test passed. Negative controls all rejected known-bad input.")
    return 0


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check whether a PumpSwap pool's migration LP tokens were "
                    "burnt in the migration transaction.",
        epilog="Exit 0 = all assertions held, 1 = an assertion is false, "
               "2 = could not check.")
    parser.add_argument("pool", nargs="?", help="the PumpSwap Pool address")
    parser.add_argument("--expect-burned", type=int, metavar="N",
                        help="assert exactly N LP base units were burnt in the "
                             "migration transaction")
    parser.add_argument("--allow-non-migrated", action="store_true",
                        help="report, rather than fail, when the pool was not "
                             "created by Pump's migrate instruction")
    parser.add_argument("--skip-transaction", action="store_true",
                        help="check account state only; do not fetch the "
                             "migration transaction")
    parser.add_argument("--survey", type=int, metavar="K", nargs="?", const=200,
                        help="sample K index-0 pools deterministically and "
                             "report outstanding LP across them (default 200). "
                             "Needs getProgramAccounts.")
    parser.add_argument("--rpc", metavar="URL", help="Solana RPC endpoint "
                        "(default: $SOLANA_RPC_URL, else public mainnet)")
    parser.add_argument("--json", metavar="PATH",
                        help="also write the decoded facts here as JSON")
    parser.add_argument("--self-test", action="store_true",
                        help="run against known-good and known-bad input and "
                             "confirm the answers are right")
    args = parser.parse_args()

    if args.self_test:
        return self_test(url=args.rpc)

    if args.survey is not None:
        try:
            survey(k=args.survey, url=args.rpc, out_path=args.json)
        except CheckerError as exc:
            print(f"\nCOULD NOT CHECK: {exc}")
            return 2
        return 0

    if not args.pool:
        parser.print_help()
        print("\nNo pool given. Try --self-test to confirm this checker works.")
        return 2

    lib.banner("lp_burn.py", args.rpc)
    try:
        checks, facts = check(args.pool,
                              expect_burned=args.expect_burned,
                              require_canonical=not args.allow_non_migrated,
                              skip_transaction=args.skip_transaction,
                              url=args.rpc)
    except CheckerError as exc:
        print(f"\nCOULD NOT CHECK: {exc}")
        return 2

    checks.print_report()
    if args.json:
        Path(args.json).write_text(json.dumps(facts, indent=2, sort_keys=True,
                                              default=str), encoding="utf-8")
        print(f"\nwrote {args.json}")

    code = checks.exit_code()
    print("")
    if code == 0:
        print("RESULT: every assertion held. The LP tokens received at "
              "migration were burnt in the migration transaction.")
    elif code == 1:
        print("RESULT: at least one assertion is FALSE. See the FAIL lines.")
    else:
        print("RESULT: incomplete — something could not be checked.")
    return code


if __name__ == "__main__":
    sys.exit(main())
