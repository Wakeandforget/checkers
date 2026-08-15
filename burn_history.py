#!/usr/bin/env python3
"""
burn_history.py — how many tokens has one account actually destroyed?

CLAIM CLASS: "we have burned N tokens" — the total of every supply-reducing
SPL-Token Burn / BurnChecked instruction authorised by one account for one
mint, decoded from the raw instruction bytes of the transactions themselves.

RUN: python3 checkers/burn_history.py --mint <MINT> --authority <ADDRESS> --expect-burned-between 133500000 134500000

What this answers
-----------------
"We burned N tokens" is one of the easiest claims in crypto to make and one of
the least often checked, because checking it means reading transactions rather
than reading a balance. Three different things get called a burn:

  * a real `Burn` instruction, which lowers `Mint::supply` — the tokens stop
    existing and no key can bring them back;
  * a transfer to a "burn address" nobody is known to hold — the tokens still
    exist, the supply is unchanged, and the claim rests on a belief about a
    private key;
  * a transfer to a treasury or a lock, described as a burn in a blog post.

Only the first is a burn. This checker counts only the first, and it counts it
per authority, so "*we* burned N" can be told apart from "N was burned by
someone".

How it reads a burn
-------------------
Three independent readings of every transaction, which must agree:

  1. **The instruction bytes.** SPL-Token instruction data is decoded here, by
     hand: the first byte is the tag (8 = Burn, 15 = BurnChecked) and the next
     eight are a little-endian u64 amount. No parser, no SDK, no explorer.
  2. **The validator's token-balance record.** `meta.preTokenBalances` and
     `meta.postTokenBalances` are written by the runtime, not by the program.
     The account burnt from must show a fall of exactly the decoded amount.
     That record also names the account's *owner at the time*, which is how the
     burn is attributed without trusting the instruction's own account list.
  3. **The mint's supply today**, decoded from the mint account's bytes, must
     be at least as large as the burns found and small enough to be consistent
     with them.

A transaction whose readings disagree is reported and fails the run. It is not
quietly averaged.

Finding the burns
-----------------
`--walk` (the default when no `--tx` is given) pages the authority's entire
signature history and fetches every transaction. That is the complete method,
and it is complete in one direction only, which the report states plainly: a
burn performed by a *delegate* on the token account would not name the
authority and would be missed. A miss can only make the true total larger, so a
total that meets a claim is evidence for it and a total that falls short is a
real shortfall.

`--tx SIG,SIG,...` checks only the named transactions. A confirmed Solana
transaction is immutable, so a command pinned to signatures gives the same
answer in a year, while a walk over a live account does not. Publish the pinned
form; run the walk to establish that the pinned form is the whole story.

Exit codes
----------
  0  every assertion held
  1  at least one assertion is false
  2  it could not be checked (network, bad input, history unreachable)
"""

import argparse
import datetime
import json
import sys

try:
    import _lib as lib
    import spl_mint
except ImportError:  # run from the repository root
    sys.path.insert(0, __file__.rsplit("/", 1)[0])
    import _lib as lib
    import spl_mint


# The two token programs. Burn is instruction 8 and BurnChecked is 15 in both;
# Token-2022 kept the original tags so that the layouts stay compatible.
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

BURN_TAG = 8
BURN_CHECKED_TAG = 15

# Instruction tags that move tokens without destroying any, kept by name so the
# report can say what a transaction did instead of only what it did not do.
TAG_NAMES = {
    3: "Transfer", 4: "Approve", 6: "SetAuthority", 7: "MintTo",
    8: "Burn", 9: "CloseAccount", 12: "TransferChecked", 14: "MintToChecked",
    15: "BurnChecked",
}


# ---------------------------------------------------------------------------
# Decoding, from bytes
# ---------------------------------------------------------------------------


def decode_token_instruction(data: bytes) -> dict:
    """Decode an SPL-Token instruction's data field. Returns {} if not a burn.

    Burn         : [8]  amount u64                       -> 9 bytes
    BurnChecked  : [15] amount u64, decimals u8          -> 10 bytes

    Anything else is returned with is_burn False rather than raising, because
    most instructions in a burn transaction are not burns and that is normal.
    """
    if not data:
        return {"is_burn": False, "tag": None, "why": "empty instruction data"}
    tag = data[0]
    name = TAG_NAMES.get(tag, f"tag {tag}")
    if tag == BURN_TAG:
        if len(data) != 9:
            raise lib.CheckerError(
                f"Burn instruction data should be 9 bytes (1 tag + 8 amount), "
                f"found {len(data)}: {data.hex()}"
            )
        return {"is_burn": True, "tag": tag, "name": "Burn",
                "amount": int.from_bytes(data[1:9], "little"), "decimals": None}
    if tag == BURN_CHECKED_TAG:
        if len(data) != 10:
            raise lib.CheckerError(
                f"BurnChecked instruction data should be 10 bytes "
                f"(1 tag + 8 amount + 1 decimals), found {len(data)}: {data.hex()}"
            )
        return {"is_burn": True, "tag": tag, "name": "BurnChecked",
                "amount": int.from_bytes(data[1:9], "little"),
                "decimals": data[9]}
    return {"is_burn": False, "tag": tag, "name": name}


def transaction_keys(tx: dict) -> list:
    """Every account key the transaction can address, in index order.

    A versioned transaction names some of its accounts in an address lookup
    table; the runtime resolves them and reports them in
    `meta.loadedAddresses`. They are appended after the static keys, writable
    first — that ordering is part of the runtime's ABI, and getting it wrong
    silently mislabels accounts, so it is done here explicitly rather than
    trusting a parser to have done it.
    """
    message = tx["transaction"]["message"]
    keys = list(message["accountKeys"])
    loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
    keys += list(loaded.get("writable") or [])
    keys += list(loaded.get("readonly") or [])
    return keys


def all_instructions(tx: dict):
    """Yield (where, instruction) for top-level and inner instructions alike.

    Inner instructions are the ones a program issued on your behalf. A burn
    performed through a CPI is exactly as real as one at the top level, and
    reading only the outer list is the standard way to undercount.
    """
    message = tx["transaction"]["message"]
    for ins in message.get("instructions") or []:
        yield "top-level", ins
    for group in (tx.get("meta") or {}).get("innerInstructions") or []:
        for ins in group.get("instructions") or []:
            yield f"inner (of instruction {group.get('index')})", ins


def token_balance_deltas(tx: dict, mint: str) -> dict:
    """The runtime's own record of who gained and lost this token, by account.

    Returns {account: {"delta": int, "owner": str|None}}. `owner` is the token
    account's owner as the validator recorded it in that transaction, which is
    what makes attribution possible for an account that has since been closed.
    """
    meta = tx.get("meta") or {}
    keys = transaction_keys(tx)
    pre = {b["accountIndex"]: b for b in meta.get("preTokenBalances") or []
           if b.get("mint") == mint}
    post = {b["accountIndex"]: b for b in meta.get("postTokenBalances") or []
            if b.get("mint") == mint}
    out = {}
    for index in sorted(set(pre) | set(post)):
        before = int(pre[index]["uiTokenAmount"]["amount"]) if index in pre else 0
        after = int(post[index]["uiTokenAmount"]["amount"]) if index in post else 0
        owner = (post.get(index) or pre.get(index) or {}).get("owner")
        account = keys[index] if index < len(keys) else f"<index {index}>"
        out[account] = {"delta": after - before, "owner": owner}
    return out


def burns_in_transaction(tx: dict, mint: str) -> dict:
    """Every burn of `mint` in one transaction, decoded from the raw bytes.

    Returns a record with the instruction-level burns, the validator's balance
    deltas, and whether the two agree.
    """
    meta = tx.get("meta") or {}
    keys = transaction_keys(tx)
    header = tx["transaction"]["message"].get("header") or {}
    signer_count = header.get("numRequiredSignatures", 0)
    signers = keys[:signer_count]

    burns = []
    for where, ins in all_instructions(tx):
        program = keys[ins["programIdIndex"]] if ins["programIdIndex"] < len(keys) else None
        if program not in (TOKEN_PROGRAM, TOKEN_2022):
            continue
        decoded = decode_token_instruction(lib.b58decode(ins["data"]))
        if not decoded.get("is_burn"):
            continue
        accounts = [keys[i] if i < len(keys) else f"<index {i}>"
                    for i in ins.get("accounts") or []]
        if len(accounts) < 3:
            raise lib.CheckerError(
                f"a {decoded['name']} instruction needs 3 accounts "
                f"(source, mint, authority), found {len(accounts)}"
            )
        source, burn_mint, authority = accounts[0], accounts[1], accounts[2]
        if burn_mint != mint:
            continue  # a burn, but of some other token
        burns.append({
            "where": where,
            "instruction": decoded["name"],
            "raw": ins["data"],
            "amount": decoded["amount"],
            "declared_decimals": decoded["decimals"],
            "source": source,
            "mint": burn_mint,
            "authority": authority,
            "extra_signers": accounts[3:],
        })

    deltas = token_balance_deltas(tx, mint)
    return {
        "signature": tx["transaction"]["signatures"][0],
        "slot": tx.get("slot"),
        "blockTime": tx.get("blockTime"),
        "err": meta.get("err"),
        "signers": signers,
        "burns": burns,
        "deltas": deltas,
        "burned_total": sum(b["amount"] for b in burns),
        # What this transaction actually destroyed. A rolled-back transaction
        # destroyed nothing however many burn instructions it contains.
        "counted_total": 0 if meta.get("err") is not None
                         else sum(b["amount"] for b in burns),
    }


def cross_read(record: dict) -> list:
    """Compare the instruction bytes against the validator's balance record.

    Returns a list of complaints; empty means the two readings agree. Every
    burn should show up as a fall in the source account of exactly that size,
    and the sum of all falls not explained by a transfer elsewhere should be
    the sum of the burns.

    A transaction that FAILED is not cross-read: the runtime rolled it back, so
    it has no balance record to agree with. A failed transaction containing a
    burn instruction is an ordinary thing, and the caller's job is simply not
    to count it. `counted_total` says what this transaction actually destroyed.
    """
    problems = []
    if record["err"] is not None:
        return problems

    net = sum(d["delta"] for d in record["deltas"].values())
    burned = record["burned_total"]
    # Tokens only leave the system through a burn. Accounts inside this
    # transaction can also send tokens to accounts outside it, which shows as a
    # fall with no matching rise, so the net can be more negative than the
    # burns — but it can never be less negative.
    if burned and net > 0:
        problems.append(
            f"instructions burn {burned} base units but the validator records "
            f"a net gain of {net} for this mint"
        )
    if burned and -net < burned:
        problems.append(
            f"instructions burn {burned} base units but the validator records "
            f"a net fall of only {-net}"
        )
    for burn in record["burns"]:
        entry = record["deltas"].get(burn["source"])
        if entry is None:
            problems.append(
                f"a burn of {burn['amount']} from {burn['source']} does not "
                "appear in the validator's token-balance record at all"
            )
        elif entry["delta"] > 0:
            problems.append(
                f"the account burnt from ({burn['source']}) gained "
                f"{entry['delta']} base units instead of losing any"
            )
    return problems


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------


TX_OPTIONS = {"encoding": "json", "maxSupportedTransactionVersion": 0}


def signatures_for(address: str, url=None, progress=None) -> list:
    """Every signature that names this account, oldest last, paged to the end."""
    out, before = [], None
    while True:
        params = {"limit": 1000}
        if before:
            params["before"] = before
        page = lib.rpc("getSignaturesForAddress", [address, params], url=url)
        out += page
        if progress:
            progress(len(out))
        if len(page) < 1000:
            return out
        before = page[-1]["signature"]


def fetch_transactions(signatures, url=None, progress=None) -> list:
    """Fetch many transactions in batches. Raises rather than skipping any."""
    params = [[s, TX_OPTIONS] for s in signatures]
    results = lib.rpc_batch("getTransaction", params, url=url, progress=progress)
    missing = [s for s, r in zip(signatures, results) if r is None]
    if missing:
        raise lib.CheckerError(
            f"{len(missing)} transaction(s) could not be fetched — the endpoint "
            f"returned null, which usually means its history has been pruned. "
            f"First: {missing[0]}. A total computed without them would be a "
            f"floor, not a total, so this run stops instead."
        )
    return results


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


def check(mint, authority=None, signatures=None, expect_burned=None,
          expect_between=None, expect_at_least=None, url=None,
          out_path=None, quiet=False) -> int:
    checks = lib.Checks()

    if not quiet:
        lib.banner("burn_history.py — supply-reducing burns, by authority", url)

    if not lib.is_valid_pubkey(mint):
        raise lib.CheckerError(f"{mint!r} is not a base58 Solana address")
    if authority is not None and not lib.is_valid_pubkey(authority):
        raise lib.CheckerError(f"{authority!r} is not a base58 Solana address")

    # The mint first: decimals come from the chain, never from the claim.
    mint_account = lib.get_account(mint, url=url)
    mint_state = spl_mint.decode_mint(mint_account["data"])
    decimals = mint_state["decimals"]
    supply = mint_state["supplyBaseUnits"]
    scale = 10 ** decimals

    if not quiet:
        print("MINT")
        print("-" * 70)
        print(f"  address:        {mint}")
        print(f"  owner program:  {mint_account['owner']}")
        print(f"  decimals:       {decimals}  (offset 44 of the mint account)")
        print(f"  supply now:     {supply} base units = {supply / scale:,.6f}")
        print(f"  mint authority: {mint_state['mintAuthority']}")
        print("")

    # Which transactions to read.
    if signatures:
        source_of_signatures = f"{len(signatures)} signature(s) named on the command line"
        sig_list = list(signatures)
        complete = False
    else:
        if not authority:
            raise lib.CheckerError(
                "give either --tx SIG,... or --authority ADDRESS so there is "
                "something to walk"
            )
        if not quiet:
            print(f"Paging every signature that names {authority} ...")
        entries = signatures_for(
            authority, url=url,
            progress=None if quiet else (lambda n: print(f"  {n} so far", flush=True)))
        sig_list = [e["signature"] for e in entries]
        source_of_signatures = (
            f"the complete signature history of {authority} "
            f"({len(sig_list)} transactions)")
        complete = True
        if not quiet:
            print("")

    if not sig_list:
        checks.blocked("burns found",
                       "the account has no transaction history at all")
        checks.print_report()
        return checks.exit_code()

    if not quiet:
        print(f"Fetching {len(sig_list)} transaction(s) ...")
    txs = fetch_transactions(
        sig_list, url=url,
        progress=None if quiet else (lambda n, t: print(f"  {n}/{t}", flush=True)))
    if not quiet:
        print("")

    records = [burns_in_transaction(tx, mint) for tx in txs]
    burning = [r for r in records if r["burns"]]
    failed_with_burns = [r for r in burning if r["err"] is not None]
    succeeded = [r for r in burning if r["err"] is None]

    # Attribution. The instruction names an authority; the validator names the
    # owner of the account burnt from. Both must point at the claimed account.
    attributed, unattributed = [], []
    for record in succeeded:
        for burn in record["burns"]:
            owner = (record["deltas"].get(burn["source"]) or {}).get("owner")
            if authority is None or burn["authority"] == authority or owner == authority:
                attributed.append((record, burn, owner))
            else:
                unattributed.append((record, burn, owner))

    total = sum(b["amount"] for _, b, _ in attributed)
    other_total = sum(b["amount"] for _, b, _ in unattributed)

    # Every transaction in which an account owned by the authority gained or
    # lost this token. This is here so that a run finding NO burns still says
    # what did happen — "the tokens were sent to a burn address" and "the
    # tokens were destroyed" look identical in a balance and completely
    # different here.
    movements = []
    for record in records:
        if record["err"] is not None:
            continue
        mine = {account: entry for account, entry in record["deltas"].items()
                if authority is None or entry["owner"] == authority}
        if not mine or all(entry["delta"] == 0 for entry in mine.values()):
            continue
        movements.append({
            "signature": record["signature"],
            "blockTime": record["blockTime"],
            "net": sum(entry["delta"] for entry in mine.values()),
            "burned": record["counted_total"],
            "counterparties": {a: e["delta"] for a, e in record["deltas"].items()
                               if a not in mine and e["delta"] != 0},
        })
    moved_out = sum(-m["net"] for m in movements if m["net"] < 0)

    problems = []
    for record in records:
        problems += [(record["signature"], p) for p in cross_read(record)]

    if not quiet:
        print("BURNS FOUND")
        print("-" * 70)
        print(f"  searched:            {source_of_signatures}")
        print(f"  transactions read:   {len(records)}")
        print(f"  containing a burn:   {len(burning)}"
              f"  ({len(failed_with_burns)} of them failed and count for nothing)")
        print(f"  attributed burns:    {len(attributed)}")
        print(f"  total burned:        {total} base units "
              f"= {total / scale:,.6f} tokens")
        if unattributed:
            print(f"  NOT attributed:      {len(unattributed)} burn(s), "
                  f"{other_total / scale:,.6f} tokens, by another authority")
        print(f"  transactions in which the authority's token balance moved at "
              f"all: {len(movements)}")
        print(f"  of that movement, left its accounts:  "
              f"{moved_out / scale:,.6f} tokens "
              f"(destroyed: {total / scale:,.6f}; the rest went somewhere and "
              f"still exists)")
        print("")
        for record, burn, owner in sorted(attributed, key=lambda r: r[0]["blockTime"] or 0):
            when = record["blockTime"]
            stamp = ""
            if when:
                stamp = datetime.datetime.fromtimestamp(
                    when, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
            print(f"  {stamp}  {burn['amount'] / scale:>18,.6f}  {burn['instruction']}"
                  f" ({burn['where']})")
            print(f"      signature:  {record['signature']}")
            print(f"      slot:       {record['slot']}")
            print(f"      from:       {burn['source']}  (owner at the time: {owner})")
            print(f"      authority:  {burn['authority']}")
            print(f"      raw data:   {burn['raw']}  -> tag {burn['instruction']}, "
                  f"amount {burn['amount']}")
            delta = (record["deltas"].get(burn["source"]) or {}).get("delta")
            print(f"      validator's balance delta for that account: {delta}")
        print("")

    # Assertions.
    checks.expect_true(
        "every burn's instruction bytes agree with the validator's balance record",
        not problems,
        "all readings agree" if not problems
        else "; ".join(f"{s[:12]}...: {p}" for s, p in problems[:4]))

    if authority is not None:
        checks.expect_true(
            f"at least one real supply-reducing burn is attributable to {authority}",
            bool(attributed),
            f"{len(attributed)} burn instruction(s) found")

    if not quiet:
        print(f"For scale: the mint's supply today is {supply / scale:,.6f} "
              f"tokens, and the burns found above are "
              f"{(total / supply * 100) if supply else 0:.4f}% of that.\n")

    if expect_burned is not None:
        checks.expect(f"total burned (base units)", total, expect_burned)
    if expect_at_least is not None:
        checks.expect_true(
            f"total burned is at least {expect_at_least / scale:,.6f} tokens",
            total >= expect_at_least,
            f"found {total / scale:,.6f} tokens ({total} base units)")
    if expect_between is not None:
        low, high = expect_between
        checks.expect_true(
            f"total burned is between {low / scale:,.6f} and {high / scale:,.6f} tokens",
            low <= total <= high,
            f"found {total / scale:,.6f} tokens ({total} base units)")

    if not complete and not quiet:
        print("NOTE: only the transactions named on the command line were read. "
              "This is a floor on what that authority has burned, not a total. "
              "Run with --authority and no --tx for the complete walk.")
    if complete and not quiet:
        print("NOTE: the walk covers every transaction naming the authority. A "
              "burn performed by a DELEGATE on the token account would not name "
              "it and would be missed; such a miss can only make the true total "
              "larger, never smaller.")

    if out_path:
        with open(out_path, "w") as handle:
            json.dump({
                "mint": mint, "decimals": decimals, "supply": supply,
                "authority": authority, "checkedAt": lib.utc_now(),
                "transactionsRead": len(records),
                "totalBurnedBaseUnits": total,
                "complete": complete,
                "burns": [{
                    "signature": r["signature"], "slot": r["slot"],
                    "blockTime": r["blockTime"], "amount": b["amount"],
                    "instruction": b["instruction"], "raw": b["raw"],
                    "source": b["source"], "authority": b["authority"],
                    "ownerAtTheTime": o, "where": b["where"],
                } for r, b, o in attributed],
                "unattributed": [{
                    "signature": r["signature"], "amount": b["amount"],
                    "authority": b["authority"], "ownerAtTheTime": o,
                } for r, b, o in unattributed],
                "movements": movements,
                "movedOutBaseUnits": moved_out,
                "crossReadProblems": problems,
            }, handle, indent=1, sort_keys=True)
        if not quiet:
            print(f"\nWrote {out_path}")

    if not quiet:
        checks.print_report()
    return checks.exit_code()


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

# All pinned to confirmed transactions and to PDA-free constants, so none of
# them can rot: a confirmed Solana transaction is immutable.

JUP_MINT = "JUPyiwrYJFskUPiHa7hkeR8VUtAeFoSYbKedZNsDvCN"
LITTERBOX = "6tZT9AUcQn4iHMH79YZEXSy55kDLQ4VbA3PMtfLVNsFX"
LITTERBOX_JUP_ACCOUNT = "DpVH8xQZ4aapxwZ6KW9nuEUs9zEePa8HQvXny9Ajj93T"

# Jupiter's burner vault: Squads v4 vault 0 of multisig
# AJJh9sZSxx5FdesW3q4bjgrWWZ3NKXkqvGc3dnE2GsYc. Every JUP burn found on chain
# by this checker's own walk was executed by it, out of the token account
# H9at42xAafMAYqWmL4sxX5EiUpECruvEsdsBc6uDJUtT.
JUP_BURNER = "8gMBNeKwXaoNi9bhbVUWFt4Uc5aobL9PeYMXfYDMePE2"

# Confirmed transactions are immutable, so none of these controls can rot.
KNOWN_BURNS = [
    # The 3,000,000,000 JUP burn announced at Catstanbul, 2025-01-26.
    ("hVMkqg6XJUrBykRF3L5JMJoVL8J3MEQrH1Apufw2oxXwXoJVN6b3U1CP71saHzghWmcPuqVyDpf6T6zMaanQQGW",
     3_000_000_000_000_000),
    # The burn of the Litterbox Trust's accumulated JUP, 2025-11-25.
    ("3avJjhdTSh8rSGRCY9FjYNRjNzJ16jwC5Q7grH9TYdm9ZU4UoC1QjsJS3T6jev9G2Jf2tp7LemAJqcgrELng2muS",
     135_023_160_919_176),
]

# The transfer that moved 134,549,949.919176 JUP out of the Litterbox Trust's
# own account the day before that burn. It is the control that matters most:
# it looks like a burn in a balance and is not one.
KNOWN_NON_BURN_TX = ("2N4izjCLi72Tuvbzxd9Anjfc6wEY7x1iB5krqwbtwhf29z"
                     "Z5GnfTnSPBgsZt2raMj71i5aBUscHCoWbmTg9vkaCQ")
KNOWN_NON_BURN_MOVED = 134_549_949_919_176


def self_test(url=None) -> int:
    """Prove the checker can fail. Every negative control is listed as such."""
    lib.banner("burn_history.py — self-test", url)
    passed = failed = 0

    def ok(label, condition, detail=""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  [ PASS ] {label}")
        else:
            failed += 1
            print(f"  [ FAIL ] {label}  {detail}")

    print("Instruction decoding, from bytes")
    print("-" * 70)
    burn = bytes([8]) + (123456789).to_bytes(8, "little")
    d = decode_token_instruction(burn)
    ok("Burn (tag 8) decodes to its amount", d["is_burn"] and d["amount"] == 123456789, d)
    checked = bytes([15]) + (5).to_bytes(8, "little") + bytes([6])
    d = decode_token_instruction(checked)
    ok("BurnChecked (tag 15) decodes amount and decimals",
       d["is_burn"] and d["amount"] == 5 and d["decimals"] == 6, d)
    d = decode_token_instruction(bytes([3]) + (1).to_bytes(8, "little"))
    ok("NEGATIVE: Transfer (tag 3) is not counted as a burn", not d["is_burn"], d)
    d = decode_token_instruction(bytes([7]) + (1).to_bytes(8, "little"))
    ok("NEGATIVE: MintTo (tag 7) is not counted as a burn", not d["is_burn"], d)
    d = decode_token_instruction(bytes([9]))
    ok("NEGATIVE: CloseAccount (tag 9) is not counted as a burn", not d["is_burn"], d)
    try:
        decode_token_instruction(bytes([8, 1, 2]))
        ok("NEGATIVE: a truncated Burn raises rather than guessing", False,
           "it returned instead of raising")
    except lib.CheckerError:
        ok("NEGATIVE: a truncated Burn raises rather than guessing", True)
    d = decode_token_instruction(bytes([8]) + (2 ** 64 - 1).to_bytes(8, "little"))
    ok("a u64 amount at its maximum decodes exactly",
       d["amount"] == 18446744073709551615, d)

    print("\nAccount-key resolution")
    print("-" * 70)
    fake = {
        "transaction": {"signatures": ["s"], "message": {
            "accountKeys": ["A", "B"], "header": {"numRequiredSignatures": 1},
            "instructions": []}},
        "meta": {"loadedAddresses": {"writable": ["C"], "readonly": ["D"]}},
    }
    ok("lookup-table addresses are appended writable-first",
       transaction_keys(fake) == ["A", "B", "C", "D"], transaction_keys(fake))
    fake_legacy = {"transaction": {"signatures": ["s"], "message": {
        "accountKeys": ["A"], "header": {"numRequiredSignatures": 1},
        "instructions": []}}, "meta": {}}
    ok("a legacy transaction with no lookup tables still resolves",
       transaction_keys(fake_legacy) == ["A"], transaction_keys(fake_legacy))

    print("\nA failed transaction destroys nothing")
    print("-" * 70)
    fake_failed = {
        "slot": 1, "blockTime": 1,
        "transaction": {"signatures": ["s"], "message": {
            "accountKeys": [TOKEN_PROGRAM, LITTERBOX_JUP_ACCOUNT, JUP_MINT, LITTERBOX],
            "header": {"numRequiredSignatures": 1},
            "instructions": [{"programIdIndex": 0, "accounts": [1, 2, 3],
                              "data": lib.b58encode(
                                  bytes([8]) + (777).to_bytes(8, "little"))}]}},
        "meta": {"err": {"InstructionError": [0, "Custom"]},
                 "preTokenBalances": [], "postTokenBalances": []},
    }
    record = burns_in_transaction(fake_failed, JUP_MINT)
    ok("NEGATIVE: a burn inside a FAILED transaction counts for nothing",
       record["burns"] and record["counted_total"] == 0 and record["burned_total"] == 777,
       record)
    ok("a failed transaction is not cross-read against a record it never wrote",
       cross_read(record) == [], cross_read(record))

    print("\nCross-reading catches a mismatch")
    print("-" * 70)
    record = {"err": None,
              "burns": [{"amount": 1000, "source": "X"}],
              "deltas": {"X": {"delta": +1000, "owner": "O"}},
              "burned_total": 1000}
    ok("NEGATIVE: instructions say burn, validator says the account GAINED",
       cross_read(record) != [], cross_read(record))
    record = {"err": None,
              "burns": [{"amount": 1000, "source": "X"}],
              "deltas": {"X": {"delta": -400, "owner": "O"}},
              "burned_total": 1000}
    ok("NEGATIVE: the validator's fall is smaller than the burn",
       cross_read(record) != [], cross_read(record))
    record = {"err": None,
              "burns": [{"amount": 1000, "source": "X"}],
              "deltas": {"X": {"delta": -1000, "owner": "O"}},
              "burned_total": 1000}
    ok("a burn matching the validator's fall exactly passes",
       cross_read(record) == [], cross_read(record))

    if not KNOWN_BURNS:
        print("\nNo pinned on-chain controls are compiled in.")
        print(f"\n{passed} passed, {failed} failed")
        return 1 if failed else 0

    print("\nPinned on-chain controls (confirmed transactions, immutable)")
    print("-" * 70)
    sigs = [s for s, _ in KNOWN_BURNS]
    txs = fetch_transactions(sigs, url=url)
    for (sig, expected), tx in zip(KNOWN_BURNS, txs):
        record = burns_in_transaction(tx, JUP_MINT)
        ok(f"{sig[:16]}... burns exactly {expected} base units of JUP",
           record["burned_total"] == expected,
           f"found {record['burned_total']}")
        ok(f"{sig[:16]}... instruction bytes agree with the validator's record",
           cross_read(record) == [], cross_read(record))
        wrong = burns_in_transaction(tx, LITTERBOX)  # not a mint: no burns of it
        ok(f"NEGATIVE: {sig[:16]}... shows no burn when a different mint is asked for",
           wrong["burned_total"] == 0, wrong["burned_total"])

    if KNOWN_NON_BURN_TX:
        tx = fetch_transactions([KNOWN_NON_BURN_TX], url=url)[0]
        record = burns_in_transaction(tx, JUP_MINT)
        ok("NEGATIVE: a large transfer OUT is not counted as a burn",
           record["burned_total"] == 0 and record["burns"] == [],
           record["burned_total"])
        moved = -sum(e["delta"] for a, e in record["deltas"].items()
                     if e["owner"] == LITTERBOX)
        ok("...even though that transfer emptied the account of "
           f"{KNOWN_NON_BURN_MOVED / 1e6:,.6f} tokens",
           moved == KNOWN_NON_BURN_MOVED, moved)
        code = check(JUP_MINT, authority=LITTERBOX,
                     signatures=[KNOWN_NON_BURN_TX], url=url, quiet=True)
        ok("NEGATIVE: checking that transfer as a burn claim exits 1",
           code == 1, f"exit {code}")

    print("\nThe assertion machinery itself can fail")
    print("-" * 70)
    code = check(JUP_MINT, authority=JUP_BURNER, signatures=[KNOWN_BURNS[0][0]],
                 expect_burned=KNOWN_BURNS[0][1] + 1, url=url, quiet=True)
    ok("NEGATIVE: a wrong --expect-burned exits 1", code == 1, f"exit {code}")
    code = check(JUP_MINT, authority=JUP_BURNER, signatures=[KNOWN_BURNS[0][0]],
                 expect_burned=KNOWN_BURNS[0][1], url=url, quiet=True)
    ok("the same run with the right figure exits 0", code == 0, f"exit {code}")
    code = check(JUP_MINT, authority=LITTERBOX, signatures=[KNOWN_BURNS[0][0]],
                 url=url, quiet=True)
    ok("NEGATIVE: the same burn attributed to the wrong authority exits 1",
       code == 1, f"exit {code}")

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


def parse_amount(text: str, decimals: int) -> int:
    """Turn "134,000,000" or "135023160.919176" into base units, exactly.

    Done with strings rather than floats on purpose: 135023160.919176 is not
    representable in binary floating point, and a claim that is out by one base
    unit because of a rounding error is a bug that looks like a finding.
    """
    cleaned = str(text).replace(",", "").replace("_", "").strip()
    if cleaned.count(".") > 1 or not cleaned.replace(".", "").isdigit():
        raise lib.CheckerError(
            f"{text!r} is not an amount of tokens. Write it in whole tokens, "
            f"like 134000000 or 135023160.919176 — not in base units."
        )
    whole, _, fraction = cleaned.partition(".")
    if len(fraction) > decimals:
        raise lib.CheckerError(
            f"{text!r} names {len(fraction)} decimal places but this mint has "
            f"only {decimals}. That amount cannot exist."
        )
    return int(whole or "0") * 10 ** decimals + int((fraction or "0").ljust(decimals, "0") or "0")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Total the supply-reducing token burns made by one account.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument("--mint", help="the token mint (base58)")
    parser.add_argument("--authority", help="the account whose burns to total")
    parser.add_argument("--tx", help="comma-separated signatures to read instead "
                                     "of walking the whole history")
    parser.add_argument("--expect-burned", metavar="TOKENS",
                        help="assert the exact total, in whole tokens")
    parser.add_argument("--expect-burned-at-least", metavar="TOKENS",
                        help="assert a floor, in whole tokens")
    parser.add_argument("--expect-burned-between", nargs=2, metavar=("LOW", "HIGH"),
                        help="assert the total lies in a range, in whole tokens")
    parser.add_argument("--rpc", metavar="URL", help="a Solana RPC endpoint")
    parser.add_argument("--json", metavar="PATH", help="write the findings here")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    url = args.rpc or None
    try:
        if args.self_test:
            return self_test(url=url)
        if not args.mint:
            parser.error("--mint is required")

        account = lib.get_account(args.mint, url=url)
        decimals = spl_mint.decode_mint(account["data"])["decimals"]
        scale = 10 ** decimals

        expect_burned = expect_at_least = expect_between = None
        if args.expect_burned:
            expect_burned = parse_amount(args.expect_burned, decimals)
        if args.expect_burned_at_least:
            expect_at_least = parse_amount(args.expect_burned_at_least, decimals)
        if args.expect_burned_between:
            expect_between = (parse_amount(args.expect_burned_between[0], decimals),
                              parse_amount(args.expect_burned_between[1], decimals))

        signatures = [s.strip() for s in args.tx.split(",") if s.strip()] if args.tx else None
        return check(args.mint, authority=args.authority, signatures=signatures,
                     expect_burned=expect_burned, expect_between=expect_between,
                     expect_at_least=expect_at_least, url=url, out_path=args.json)
    except lib.CheckerError as exc:
        print(f"\nCOULD NOT CHECK: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 2


if __name__ == "__main__":
    sys.exit(main())
