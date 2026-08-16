#!/usr/bin/env python3
"""
fee_split.py — is the advertised cut of trading fees the cut the chain takes?

CLAIM CLASS: "N% of our trading fees go to <somewhere>" — the fee split a
protocol advertises, read out of the configuration accounts that actually
govern it, across *every* live config rather than one flattering example; plus
whether the address the protocol names as the destination really holds what it
is said to hold.

RUN: python3 checkers/fee_split.py --venue raydium-clmm --expect-protocol-share 12 --expect-fund-share 4

What this answers
-----------------
A fee split is one of the few marketing numbers in crypto that is a literal
integer in a literal account. "12% of trading fees are used to buy back our
token" is not a promise about the future; it is a rate that a program reads on
every swap. Either the account says 120000-out-of-1000000 or it does not.

Three things have to be true before "12%" means anything, and this checker
separates them:

  1. **The rate.** What integer is in the config account, and against what
     denominator, and is it a fraction of the *fee* or of the *trade*? Those
     are different claims by a factor of about four hundred.
  2. **The coverage.** One config account proves nothing about a venue with
     twenty fee tiers, or seven hundred thousand pools. This checker reads
     every config account of the program and reports the distribution, so a
     single deviant tier cannot hide behind an average.
  3. **The destination.** A carve-out that lands nowhere is not a carve-out.
     `--holds` reads the balance the named address actually has, and
     `--trajectory` walks its history to see whether the balance only ever
     rises or whether things also leave.

What this cannot tell you
-------------------------
* **That the collected fee was spent the way it was said to be spent.** The
  chain shows a rate, a collection address and a destination balance. Tying
  every collected dollar to a purchase is a full flow reconciliation across
  intermediary wallets and swap routes; this checker does not attempt it and
  says so rather than implying otherwise.
* **That the rate will still be 12% tomorrow.** These are mutable admin
  parameters, not constants in the program. The checker prints the account
  that can change each one. Read that line.
* **Anything about a venue it has no layout for.** Layouts are pinned to
  published program source, per venue, below. There is no generic mode and
  there should not be: guessing at an offset is how you publish a wrong number
  with confidence.

Where the layouts come from
---------------------------
Nothing here comes from an explorer, an SDK or a `jsonParsed` account view.
Every offset is taken from the program's own published source, pinned to a
commit:

  raydium-clmm    programs/amm/src/states/config.rs
                  @51fdba2cf614d66a2ece9c077f1e7bf86a2875f1
  raydium-cp-swap programs/cp-swap/src/states/config.rs
                  @78f254e1023751e706df7dc15c453fc3e046697c
  raydium-amm     program/src/state.rs (AmmInfo, Fees)
                  @27f461dd439086c774055f771b253fb0fbc52008

and the meaning of each rate — fraction of the fee, not of the trade — from
the code that applies it:

  cp-swap  curve/calculator.rs: protocol_fee = Fees::protocol_fee(trade_fee, rate)
           curve/fees.rs:       floor_div(amount, rate, FEE_RATE_DENOMINATOR_VALUE)
  clmm     instructions/swap.rs `spilt_fees`:
           protocol_fee_delta = fee * protocol_fee_rate / FEE_RATE_DENOMINATOR
  amm v4   processor.rs: delta = diff * fees.pnl_numerator / fees.pnl_denominator

Exit 0 = every assertion held, 1 = an assertion is false, 2 = could not check.
"""

import argparse
import base64
import json
import os
import struct
import sys
from fractions import Fraction

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _lib import (  # noqa: E402
    CheckerError, Checks, Cursor, anchor_discriminator, b58encode, banner,
    find_program_address, parse_pubkey, rpc, rpc_batch, rpc_url, utc_now,
)

SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

# ---------------------------------------------------------------------------
# Venues
# ---------------------------------------------------------------------------
# A venue is: a program, an account layout, and the arithmetic that turns the
# integers in that account into a percentage. Adding one means reading its
# source, not guessing.

VENUES = {
    "raydium-clmm": {
        "program": "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK",
        "label": "Raydium CLMM (concentrated liquidity)",
        "kind": "amm-config",
        "size": 117,
        "denominator": 1_000_000,
        "source": "raydium-clmm programs/amm/src/states/config.rs "
                  "@51fdba2cf614d66a2ece9c077f1e7bf86a2875f1",
    },
    "raydium-cpmm": {
        "program": "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C",
        "label": "Raydium CPMM (standard constant-product)",
        "kind": "amm-config",
        "size": 236,
        "denominator": 1_000_000,
        "source": "raydium-cp-swap programs/cp-swap/src/states/config.rs "
                  "@78f254e1023751e706df7dc15c453fc3e046697c",
    },
    "raydium-amm-v4": {
        "program": "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8",
        "label": "Raydium Standard AMM v4 (legacy)",
        "kind": "per-pool",
        "size": 752,
        "fees_offset": 128,
        "config_seed": b"amm_config_account_seed",
        "source": "raydium-amm program/src/state.rs "
                  "@27f461dd439086c774055f771b253fb0fbc52008",
    },
}


# ---------------------------------------------------------------------------
# Decoders
# ---------------------------------------------------------------------------


def decode_clmm_config(address: str, data: bytes) -> dict:
    """CLMM AmmConfig. 117 bytes: 8-byte anchor discriminator then the struct.

        bump u8 | index u16 | owner Pubkey | protocol_fee_rate u32 |
        trade_fee_rate u32 | tick_spacing u16 | fund_fee_rate u32 |
        padding_u32 u32 | fund_owner Pubkey | padding [u64; 3]
    """
    cursor = Cursor(data, f"CLMM AmmConfig {address}")
    cursor.expect_discriminator("AmmConfig")
    out = {
        "address": address,
        "bump": cursor.u8(),
        "index": cursor.u16(),
        "owner": cursor.pubkey(),
        "protocol_fee_rate": cursor.u32(),
        "trade_fee_rate": cursor.u32(),
        "tick_spacing": cursor.u16(),
        "fund_fee_rate": cursor.u32(),
        "padding_u32": cursor.u32(),
        "fund_owner": cursor.pubkey(),
    }
    tail = cursor.take(24)
    if cursor.remaining:
        raise CheckerError(
            f"CLMM AmmConfig {address}: {cursor.remaining} bytes left over after "
            "the whole struct. The layout does not match this account."
        )
    out["trailing_padding_is_zero"] = (tail == b"\x00" * 24)
    _sanity_rates(out, 1_000_000, address)
    return out


def decode_cpmm_config(address: str, data: bytes) -> dict:
    """CPMM AmmConfig. 236 bytes: 8-byte anchor discriminator then the struct.

        bump u8 | disable_create_pool bool | index u16 | trade_fee_rate u64 |
        protocol_fee_rate u64 | fund_fee_rate u64 | create_pool_fee u64 |
        protocol_owner Pubkey | fund_owner Pubkey | creator_fee_rate u64 |
        padding [u64; 15]
    """
    cursor = Cursor(data, f"CPMM AmmConfig {address}")
    cursor.expect_discriminator("AmmConfig")
    out = {"address": address, "bump": cursor.u8()}
    flag = cursor.u8()
    if flag not in (0, 1):
        raise CheckerError(
            f"CPMM AmmConfig {address}: disable_create_pool is a Rust bool and "
            f"must be 0 or 1, found {flag}. The layout is wrong."
        )
    out["disable_create_pool"] = bool(flag)
    out["index"] = cursor.u16()
    out["trade_fee_rate"] = cursor.u64()
    out["protocol_fee_rate"] = cursor.u64()
    out["fund_fee_rate"] = cursor.u64()
    out["create_pool_fee"] = cursor.u64()
    out["owner"] = cursor.pubkey()          # protocol_owner
    out["fund_owner"] = cursor.pubkey()
    out["creator_fee_rate"] = cursor.u64()
    cursor.take(120)
    if cursor.remaining:
        raise CheckerError(
            f"CPMM AmmConfig {address}: {cursor.remaining} bytes left over after "
            "the whole struct. The layout does not match this account."
        )
    _sanity_rates(out, 1_000_000, address)
    return out


def _sanity_rates(config: dict, denominator: int, address: str) -> None:
    """Rates that cannot be real are a sign the offsets are wrong.

    A fee rate above 100% is not a scandal, it is a misread. This is the guard
    that makes an off-by-one offset fail loudly instead of producing a number
    that looks like journalism.
    """
    for field in ("protocol_fee_rate", "fund_fee_rate", "trade_fee_rate"):
        value = config.get(field)
        if value is None:
            continue
        if value > denominator:
            raise CheckerError(
                f"{address}: {field} decodes to {value:,}, which is more than "
                f"the denominator {denominator:,} — i.e. over 100%. These bytes "
                "are not the field this layout says they are."
            )
    if config["protocol_fee_rate"] + config["fund_fee_rate"] > denominator:
        raise CheckerError(
            f"{address}: protocol_fee_rate + fund_fee_rate is more than the "
            "whole fee. The layout is wrong."
        )


V4_FEE_FIELDS = ("min_separate_numerator", "min_separate_denominator",
                 "trade_fee_numerator", "trade_fee_denominator",
                 "pnl_numerator", "pnl_denominator",
                 "swap_fee_numerator", "swap_fee_denominator")


def decode_v4_fees(data: bytes, address: str = "amm v4 pool") -> dict:
    """AMM v4 `Fees`: eight little-endian u64, 64 bytes, at offset 128 of AmmInfo.

    v4 keeps no shared config: every pool carries its own copy, which is why
    this one has to be checked by census rather than by reading one account.
    """
    if len(data) != 64:
        raise CheckerError(
            f"{address}: a v4 Fees struct is 64 bytes, got {len(data)}.")
    values = struct.unpack("<8Q", data)
    out = dict(zip(V4_FEE_FIELDS, values))
    if all(v == 0 for v in values):
        out["initialised"] = False
        return out
    out["initialised"] = True
    for numerator, denominator in (("trade_fee_numerator", "trade_fee_denominator"),
                                   ("pnl_numerator", "pnl_denominator"),
                                   ("swap_fee_numerator", "swap_fee_denominator")):
        if out[denominator] == 0:
            raise CheckerError(f"{address}: {denominator} is zero — misread bytes.")
        if out[numerator] > out[denominator]:
            raise CheckerError(
                f"{address}: {numerator}={out[numerator]} exceeds "
                f"{denominator}={out[denominator]}, i.e. a fee over 100%. "
                "These bytes are not a Fees struct.")
    return out


# ---------------------------------------------------------------------------
# Census
# ---------------------------------------------------------------------------


def census_amm_config(venue_key: str, url: str = None) -> dict:
    """Every AmmConfig account of a CLMM/CPMM-shaped program, decoded."""
    venue = VENUES[venue_key]
    accounts = rpc("getProgramAccounts",
                   [venue["program"],
                    {"encoding": "base64",
                     "filters": [{"dataSize": venue["size"]}]}],
                   url=url, timeout=90)
    if not isinstance(accounts, list) or not accounts:
        raise CheckerError(
            f"{venue_key}: the endpoint returned no {venue['size']}-byte accounts "
            f"for {venue['program']}. Either the program has no config accounts "
            "(it should) or getProgramAccounts was refused.")
    decoder = decode_clmm_config if venue_key == "raydium-clmm" else decode_cpmm_config
    configs = []
    for item in accounts:
        raw = base64.b64decode(item["account"]["data"][0])
        configs.append(decoder(item["pubkey"], raw))
    configs.sort(key=lambda c: c["index"])
    return {"venue": venue_key, "program": venue["program"],
            "denominator": venue["denominator"], "configs": configs,
            "count": len(configs)}


def census_v4_pools(url: str = None, progress=True) -> dict:
    """Every AMM v4 pool's fee struct, read with a 64-byte dataSlice.

    705,000-odd accounts at 64 bytes each is about 60 MB on the wire and takes
    ten to twenty seconds. The alternative — sampling — cannot answer "do any
    pools differ", which is the only interesting version of the question.
    """
    venue = VENUES["raydium-amm-v4"]
    accounts = rpc("getProgramAccounts",
                   [venue["program"],
                    {"encoding": "base64",
                     "filters": [{"dataSize": venue["size"]}],
                     "dataSlice": {"offset": venue["fees_offset"], "length": 64}}],
                   url=url, timeout=600)
    if not isinstance(accounts, list) or not accounts:
        raise CheckerError(
            "amm v4: getProgramAccounts returned nothing. On a rate-limited "
            "endpoint this call is sometimes refused outright; that is 'could "
            "not check', not 'no pools'.")
    tally = {}
    uninitialised = 0
    for item in accounts:
        raw = base64.b64decode(item["account"]["data"][0])
        fees = decode_v4_fees(raw, item["pubkey"])
        if not fees["initialised"]:
            uninitialised += 1
            continue
        key = tuple(fees[f] for f in V4_FEE_FIELDS)
        entry = tally.setdefault(key, {"count": 0, "example": item["pubkey"]})
        entry["count"] += 1
    return {"venue": "raydium-amm-v4", "program": venue["program"],
            "pools": len(accounts), "uninitialised": uninitialised,
            "variants": [{"fees": dict(zip(V4_FEE_FIELDS, key)), **value}
                         for key, value in sorted(tally.items(),
                                                  key=lambda kv: -kv[1]["count"])]}


def v4_slice_control(url: str = None) -> dict:
    """Prove the dataSlice offset lines up with the full account.

    A census built on a dataSlice is a census built on one integer being right.
    So: fetch one pool whole, fetch the same pool sliced, and require the 64
    bytes to be identical. If they are not, every number above is fiction.
    """
    venue = VENUES["raydium-amm-v4"]
    sample = rpc("getProgramAccounts",
                 [venue["program"],
                  {"encoding": "base64",
                   "filters": [{"dataSize": venue["size"]}],
                   "dataSlice": {"offset": 0, "length": 0}}],
                 url=url, timeout=600)
    if not sample:
        raise CheckerError("amm v4: no pools returned for the slice control.")
    address = sample[0]["pubkey"]
    whole = rpc("getAccountInfo", [address, {"encoding": "base64"}], url=url)["value"]
    if whole is None:
        raise CheckerError(f"amm v4: pool {address} vanished between calls.")
    whole_bytes = base64.b64decode(whole["data"][0])
    sliced = rpc("getAccountInfo",
                 [address, {"encoding": "base64",
                            "dataSlice": {"offset": venue["fees_offset"],
                                          "length": 64}}], url=url)["value"]
    sliced_bytes = base64.b64decode(sliced["data"][0])
    offset = venue["fees_offset"]
    return {"pool": address,
            "account_len": len(whole_bytes),
            "agrees": whole_bytes[offset:offset + 64] == sliced_bytes,
            "fees": decode_v4_fees(sliced_bytes, address)}


def v4_config(url: str = None) -> dict:
    """The single v4 config account: who may withdraw the protocol's cut."""
    venue = VENUES["raydium-amm-v4"]
    pda, bump = find_program_address([venue["config_seed"]],
                                     parse_pubkey(venue["program"]))
    address = b58encode(pda)
    value = rpc("getAccountInfo", [address, {"encoding": "base64"}], url=url)["value"]
    if value is None:
        raise CheckerError(f"amm v4: config PDA {address} does not exist.")
    if value["owner"] != venue["program"]:
        raise CheckerError(
            f"amm v4: config PDA {address} is owned by {value['owner']}, not the "
            "AMM program. Wrong seed.")
    data = base64.b64decode(value["data"][0])
    # AmmConfig (v4): pnl_owner Pubkey | cancel_owner Pubkey | pending_1 [u64;28]
    #                 | pending_2 [u64;31] | create_pool_fee u64
    expected = 32 + 32 + 28 * 8 + 31 * 8 + 8
    if len(data) != expected:
        raise CheckerError(
            f"amm v4 config {address}: {len(data)} bytes, expected {expected}.")
    return {"address": address, "bump": bump,
            "pnl_owner": b58encode(data[0:32]),
            "cancel_owner": b58encode(data[32:64]),
            "create_pool_fee_lamports": struct.unpack_from("<Q", data, len(data) - 8)[0]}


# ---------------------------------------------------------------------------
# The destination: what does the named address actually hold?
# ---------------------------------------------------------------------------


def mint_decimals(mint: str, url: str = None) -> int:
    value = rpc("getAccountInfo", [mint, {"encoding": "base64"}], url=url)["value"]
    if value is None:
        raise CheckerError(f"mint {mint} does not exist.")
    data = base64.b64decode(value["data"][0])
    if len(data) < 45:
        raise CheckerError(f"{mint} is {len(data)} bytes; an SPL mint is at least 82.")
    return data[44]


def holdings(owner: str, mint: str, url: str = None) -> dict:
    """Every token account of `mint` owned by `owner`, decoded from raw bytes.

    The balance is read out of the 165-byte SPL token account layout here
    (mint at 0, owner at 32, amount at 64) rather than taken from the node's
    parsed view, and then cross-checked against getTokenAccountBalance — a
    different RPC method reading the same account. Two methods agreeing is the
    control; one method is a hope.
    """
    parse_pubkey(owner)
    parse_pubkey(mint)
    found = rpc("getTokenAccountsByOwner",
                [owner, {"mint": mint}, {"encoding": "base64"}], url=url)["value"]
    accounts = []
    total = 0
    for item in found:
        raw = base64.b64decode(item["account"]["data"][0])
        if len(raw) < 72:
            raise CheckerError(
                f"token account {item['pubkey']} is {len(raw)} bytes; too short "
                "to be an SPL token account.")
        held_mint = b58encode(raw[0:32])
        held_owner = b58encode(raw[32:64])
        amount = struct.unpack_from("<Q", raw, 64)[0]
        if held_mint != mint or held_owner != owner:
            raise CheckerError(
                f"token account {item['pubkey']} decodes to mint {held_mint} / "
                f"owner {held_owner}, which is not what was asked for. The "
                "layout or the endpoint is wrong.")
        accounts.append({"address": item["pubkey"], "amount": amount})
        total += amount
    accounts.sort(key=lambda a: -a["amount"])
    decimals = mint_decimals(mint, url=url)
    cross = None
    if accounts:
        reported = rpc("getTokenAccountBalance", [accounts[0]["address"]], url=url)
        cross = int(reported["value"]["amount"])
        if cross != accounts[0]["amount"]:
            raise CheckerError(
                f"{accounts[0]['address']}: the raw account bytes say "
                f"{accounts[0]['amount']} but getTokenAccountBalance says "
                f"{cross}. Two readings of one account disagree; nothing here "
                "can be trusted until that is explained.")
    return {"owner": owner, "mint": mint, "decimals": decimals,
            "accounts": accounts, "total": total,
            "total_tokens": total / (10 ** decimals),
            "cross_checked_largest": cross}


def signatures_for(address: str, url: str = None, limit_pages: int = 60) -> list:
    """Every signature that touched an account, newest first."""
    out = []
    before = None
    for _ in range(limit_pages):
        params = {"limit": 1000}
        if before:
            params["before"] = before
        page = rpc("getSignaturesForAddress", [address, params], url=url, timeout=60)
        if not page:
            break
        out += [{"signature": item["signature"], "blockTime": item.get("blockTime"),
                 "err": item.get("err") is not None} for item in page]
        before = page[-1]["signature"]
        if len(page) < 1000:
            break
    else:
        raise CheckerError(
            f"{address}: more than {limit_pages * 1000} signatures; refusing to "
            "walk further rather than silently reporting a partial history.")
    return out


def account_keys(transaction: dict) -> list:
    """Every account a transaction touched, in the order the indices count.

    Address-lookup-table transactions carry part of their account list in
    `meta.loadedAddresses`, appended after the message's own keys, writable
    first. Getting that order wrong silently mislabels balances, so it is done
    once, here.
    """
    message = transaction["transaction"]["message"]
    keys = [key["pubkey"] if isinstance(key, dict) else key
            for key in message["accountKeys"]]
    loaded = (transaction.get("meta") or {}).get("loadedAddresses") or {}
    return keys + list(loaded.get("writable", [])) + list(loaded.get("readonly", []))


def balance_at(transaction: dict, account: str, owner: str, mint: str, which: str):
    """The token account's balance as the validator recorded it in one transaction.

    `meta.postTokenBalances` is written by the runtime, not by the program and
    not by an indexer. The entry is found by resolving its `accountIndex` to an
    address and matching the token account itself — not by matching the owner
    field, which validators did not write before 2022 and which is therefore
    missing from the early history of any account old enough to matter. Where
    the mint and owner fields *are* present they must agree, or this raises.
    """
    meta = transaction.get("meta") or {}
    entries = meta.get(which)
    if entries is None:
        raise CheckerError(f"transaction has no {which}; cannot read a balance.")
    keys = account_keys(transaction)
    for entry in entries:
        index = entry.get("accountIndex")
        if index is None or index >= len(keys) or keys[index] != account:
            continue
        if entry.get("mint") not in (None, mint):
            raise CheckerError(
                f"{account} is recorded holding mint {entry.get('mint')} in this "
                f"transaction, not {mint}. Two readings disagree.")
        if entry.get("owner") not in (None, owner):
            raise CheckerError(
                f"{account} is recorded owned by {entry.get('owner')} in this "
                f"transaction, not {owner}. Ownership changed, or the account "
                "list was resolved wrongly.")
        return int(entry["uiTokenAmount"]["amount"])
    return None


def trajectory(owner: str, mint: str, checkpoints: int = 100, url: str = None,
               drill_limit: int = 400) -> dict:
    """Did the balance ever fall?

    Every token account of the mint that the owner holds is walked separately.
    Per-account monotonicity is a stronger statement than monotonicity of the
    total and a far cheaper one to establish: if no account ever fell, the
    total never fell either, and no interleaving of six histories is needed.
    """
    held = holdings(owner, mint, url=url)
    if not held["accounts"]:
        raise CheckerError(f"{owner} holds no token account for {mint}.")
    walks = [_trajectory_one(account["address"], owner, mint, checkpoints, url,
                             drill_limit)
             for account in held["accounts"]]
    return {"owner": owner, "mint": mint, "decimals": held["decimals"],
            "total": held["total"], "accounts": walks,
            "monotonic": all(walk["monotonic"] for walk in walks),
            "falls": sum(walk["falls"] for walk in walks),
            "transactions": sum(walk["transactions"] for walk in walks)}


def _trajectory_one(account: str, owner: str, mint: str, checkpoints: int,
                    url: str, drill_limit: int) -> dict:
    """One token account's balance at every Nth transaction of its history.

    Walking 45,000 transactions is hours of polite RPC. Walking every Nth one
    is minutes, and it answers a slightly weaker question honestly: the balance
    at each checkpoint, and whether it ever went down between two of them. If
    it did, the window between those two checkpoints is walked in full and the
    exact outgoing transactions are named. The gap is reported, because "no
    fall seen at 100 checkpoints" allows an outflow that was repaid within one
    gap, and pretending otherwise would be the kind of clean-looking answer
    this project exists to avoid.
    """
    signatures = signatures_for(account, url=url)
    if not signatures:
        raise CheckerError(f"{account} has no transaction history.")
    oldest_first = list(reversed(signatures))
    total = len(oldest_first)
    step = max(1, total // max(1, checkpoints - 1))
    indices = sorted(set(list(range(0, total, step)) + [total - 1]))
    chosen = [oldest_first[i] for i in indices]
    fetched = rpc_batch("getTransaction",
                        [[item["signature"],
                          {"encoding": "jsonParsed",
                           "maxSupportedTransactionVersion": 0}]
                         for item in chosen], url=url, chunk=25, timeout=120)
    series = []
    unreadable = []
    for index, item, transaction in zip(indices, chosen, fetched):
        if transaction is None:
            raise CheckerError(
                f"the endpoint has no record of {item['signature']}; it may be "
                "pruned. A gap in the series is not a clean series.")
        post = balance_at(transaction, account, owner, mint, "postTokenBalances")
        if post is None:
            # Transactions from before mid-2021 carry no token-balance metadata
            # at all, and some later ones only reference an account without
            # recording a balance for it. That is a checkpoint we cannot read,
            # which is different from a checkpoint that reads zero. Drop it,
            # count it, and refuse if it happens to a lot of them.
            unreadable.append(item["signature"])
            continue
        series.append({"i": index, "signature": item["signature"],
                       "blockTime": item["blockTime"], "post": post})
    if len(series) < 2:
        raise CheckerError(
            f"{account}: only {len(series)} of {len(chosen)} checkpoints carried "
            "a readable balance. There is no trajectory to report.")
    if len(unreadable) > len(chosen) // 4:
        raise CheckerError(
            f"{account}: {len(unreadable)} of {len(chosen)} checkpoints carried "
            "no balance record. Too much of the history is unreadable to call "
            "the rest a trajectory.")
    falls = [(series[k], series[k + 1]) for k in range(len(series) - 1)
             if series[k + 1]["post"] < series[k]["post"]]
    drilled = []
    for before_point, after_point in falls[:3]:
        window = oldest_first[before_point["i"]: after_point["i"] + 1]
        if len(window) > drill_limit:
            drilled.append({"window": [before_point["i"], after_point["i"]],
                            "skipped": f"{len(window)} transactions, over the "
                                       f"{drill_limit} drill limit"})
            continue
        txs = rpc_batch("getTransaction",
                        [[item["signature"],
                          {"encoding": "jsonParsed",
                           "maxSupportedTransactionVersion": 0}]
                         for item in window], url=url, chunk=25, timeout=120)
        outflows = []
        for item, transaction in zip(window, txs):
            if transaction is None:
                continue
            pre = balance_at(transaction, account, owner, mint, "preTokenBalances")
            post = balance_at(transaction, account, owner, mint, "postTokenBalances")
            if pre is None or post is None or post >= pre:
                continue
            outflows.append({"signature": item["signature"],
                             "blockTime": item["blockTime"],
                             "amount": pre - post})
        drilled.append({"window": [before_point["i"], after_point["i"]],
                        "outflows": outflows})
    return {"account": account, "transactions": total, "checkpoints": len(series),
            "largest_gap": step, "series": series,
            "first": series[0], "last": series[-1],
            "monotonic": not falls, "falls": len(falls), "drilled": drilled}


def series_falls(values) -> list:
    """The pure part of the monotonicity test, so it can be tested without a network."""
    return [k for k in range(len(values) - 1) if values[k + 1] < values[k]]


# ---------------------------------------------------------------------------
# Percentages
# ---------------------------------------------------------------------------


def parse_percent(text) -> Fraction:
    """'12', '12%' and '12.0' all mean the fraction 12/100. 'a lot' raises."""
    if isinstance(text, (int, float)):
        text = str(text)
    cleaned = str(text).strip().rstrip("%").replace(",", "").strip()
    if not cleaned:
        raise CheckerError(f"{text!r} is not a percentage.")
    try:
        return Fraction(cleaned) / 100
    except (ValueError, ZeroDivisionError):
        raise CheckerError(
            f"{text!r} is not a percentage this can compare against an integer "
            "rate. Write it as 12 or 12%.")


def as_percent(fraction: Fraction) -> str:
    value = float(fraction) * 100
    return f"{value:g}%"


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def report_amm_config_census(census: dict, checks: Checks, expect_protocol,
                             expect_fund, expect_create_pool_fee) -> None:
    venue = VENUES[census["venue"]]
    denominator = census["denominator"]
    print(f"{venue['label']}")
    print(f"  program     {census['program']}")
    print(f"  layout      {venue['source']}")
    print(f"  config accounts found: {census['count']}"
          f" (every {venue['size']}-byte account owned by the program)")
    print("")
    print("  idx  trade fee    protocol share   fund share    config account")
    print("  " + "-" * 76)
    protocol_shares = set()
    fund_shares = set()
    create_fees = set()
    owners = set()
    fund_owners = set()
    for config in census["configs"]:
        protocol = Fraction(config["protocol_fee_rate"], denominator)
        fund = Fraction(config["fund_fee_rate"], denominator)
        trade = Fraction(config["trade_fee_rate"], denominator)
        protocol_shares.add(protocol)
        fund_shares.add(fund)
        owners.add(config["owner"])
        fund_owners.add(config["fund_owner"])
        if "create_pool_fee" in config:
            create_fees.add(config["create_pool_fee"])
        print(f"  {config['index']:>3}  {as_percent(trade):>9}    "
              f"{config['protocol_fee_rate']:>7,} = {as_percent(protocol):<7} "
              f"{config['fund_fee_rate']:>6,} = {as_percent(fund):<7} "
              f"{config['address']}")
    print("")
    print(f"  distinct protocol shares: "
          f"{', '.join(sorted(as_percent(s) for s in protocol_shares))}")
    print(f"  distinct fund shares:     "
          f"{', '.join(sorted(as_percent(s) for s in fund_shares))}")
    print(f"  fee-collection signer(s): {', '.join(sorted(owners))}")
    print(f"  fund signer(s):           {', '.join(sorted(fund_owners))}")
    if create_fees:
        print(f"  pool creation fee:        "
              f"{', '.join(f'{v/1e9:g} SOL' for v in sorted(create_fees))}")
    print("")

    if expect_protocol is not None:
        checks.expect(
            f"{census['venue']}: every config takes the same protocol share of "
            f"the trading fee, and it is {as_percent(expect_protocol)}",
            ", ".join(sorted(as_percent(s) for s in protocol_shares)),
            as_percent(expect_protocol))
    if expect_fund is not None:
        checks.expect(
            f"{census['venue']}: every config takes the same fund/treasury share "
            f"of the trading fee, and it is {as_percent(expect_fund)}",
            ", ".join(sorted(as_percent(s) for s in fund_shares)),
            as_percent(expect_fund))
    if expect_create_pool_fee is not None and create_fees:
        checks.expect(
            f"{census['venue']}: pool creation fee",
            ", ".join(f"{v/1e9:g} SOL" for v in sorted(create_fees)),
            f"{expect_create_pool_fee:g} SOL")


def report_v4_census(census: dict, control: dict, config: dict, checks: Checks,
                     expect_protocol, expect_trade_fee, expect_create_pool_fee) -> None:
    venue = VENUES["raydium-amm-v4"]
    print(f"{venue['label']}")
    print(f"  program     {census['program']}")
    print(f"  layout      {venue['source']}")
    print(f"  pool accounts found:  {census['pools']:,} "
          f"({venue['size']}-byte accounts)")
    print(f"  uninitialised (all-zero fee struct): {census['uninitialised']:,}")
    print("")
    print(f"  dataSlice control: pool {control['pool']} fetched whole "
          f"({control['account_len']} bytes) and sliced at offset "
          f"{venue['fees_offset']}")
    print(f"    the 64 bytes agree: {control['agrees']}")
    print("")
    print("  distinct fee structs across every pool:")
    for variant in census["variants"]:
        fees = variant["fees"]
        pnl = Fraction(fees["pnl_numerator"], fees["pnl_denominator"])
        swap = Fraction(fees["swap_fee_numerator"], fees["swap_fee_denominator"])
        print(f"    {variant['count']:>9,} pools  "
              f"swap fee {fees['swap_fee_numerator']}/{fees['swap_fee_denominator']}"
              f" = {as_percent(swap):<7} "
              f"protocol (pnl) {fees['pnl_numerator']}/{fees['pnl_denominator']}"
              f" = {as_percent(pnl):<6}  e.g. {variant['example']}")
    print("")
    print(f"  v4 config account {config['address']} (PDA of "
          f"\"amm_config_account_seed\", bump {config['bump']})")
    print(f"    pnl_owner       {config['pnl_owner']}  "
          "— the only key that may withdraw the protocol's cut")
    print(f"    cancel_owner    {config['cancel_owner']}")
    print(f"    create_pool_fee {config['create_pool_fee_lamports']/1e9:g} SOL")
    print("")

    checks.expect_true(
        "amm v4: the 64 bytes read by dataSlice are the same 64 bytes as in the "
        "whole account (if this fails, the census below is meaningless)",
        control["agrees"], f"pool {control['pool']}")
    pnl_shares = {Fraction(v["fees"]["pnl_numerator"], v["fees"]["pnl_denominator"])
                  for v in census["variants"]}
    swap_fees = {Fraction(v["fees"]["swap_fee_numerator"],
                          v["fees"]["swap_fee_denominator"])
                 for v in census["variants"]}
    if expect_protocol is not None:
        checks.expect(
            f"amm v4: every one of the {census['pools'] - census['uninitialised']:,} "
            f"initialised pools takes the same protocol share, and it is "
            f"{as_percent(expect_protocol)}",
            ", ".join(sorted(as_percent(s) for s in pnl_shares)),
            as_percent(expect_protocol))
    if expect_trade_fee is not None:
        checks.expect(
            "amm v4: every initialised pool charges the same swap fee",
            ", ".join(sorted(as_percent(s) for s in swap_fees)),
            as_percent(expect_trade_fee))
    if expect_create_pool_fee is not None:
        checks.expect(
            "amm v4: pool creation fee in the config account",
            f"{config['create_pool_fee_lamports']/1e9:g} SOL",
            f"{expect_create_pool_fee:g} SOL")


def report_holdings(held: dict, checks: Checks, expect_at_least, label: str) -> None:
    print(f"{label}")
    print(f"  owner   {held['owner']}")
    print(f"  mint    {held['mint']}  ({held['decimals']} decimals)")
    print(f"  token accounts of that mint: {len(held['accounts'])}")
    for account in held["accounts"]:
        print(f"    {account['address']}  {account['amount']:,} base units "
              f"= {account['amount']/10**held['decimals']:,.6f}")
    print(f"  total   {held['total']:,} base units = {held['total_tokens']:,.6f}")
    if held["cross_checked_largest"] is not None:
        print(f"  control: getTokenAccountBalance on the largest account returns "
              f"{held['cross_checked_largest']:,} — the raw bytes agree")
    print("")
    if expect_at_least is not None:
        checks.expect_true(
            f"{held['owner']} holds at least {expect_at_least:,.0f} tokens of "
            f"{held['mint']}",
            held["total_tokens"] >= expect_at_least,
            f"holds {held['total_tokens']:,.6f}")


def report_trajectory(walk: dict, checks: Checks, require_monotonic: bool) -> None:
    decimals = walk["decimals"]
    print("BALANCE TRAJECTORY")
    print(f"  {len(walk['accounts'])} token accounts, "
          f"{walk['transactions']:,} transactions between them")
    print("")
    widest = 0
    for one in walk["accounts"]:
        first, last = one["first"], one["last"]
        print(f"  {one['account']}")
        print(f"    history {one['transactions']:>7,} transactions, "
              f"{one['checkpoints']} checkpoints, "
              f"every {one['largest_gap']} transactions")
        print(f"    oldest checkpoint {first['post']/10**decimals:>18,.6f}  "
              f"{first['signature']}")
        print(f"    newest checkpoint {last['post']/10**decimals:>18,.6f}  "
              f"{last['signature']}")
        print(f"    fell between checkpoints: {one['falls']} times")
        widest = max(widest, one["largest_gap"])
        for drill in one["drilled"]:
            if "skipped" in drill:
                print(f"      window {drill['window']}: {drill['skipped']}")
                continue
            for outflow in drill["outflows"]:
                print(f"      OUT {outflow['amount']/10**decimals:,.6f} in "
                      f"{outflow['signature']}")
    print("")
    print("  What this does and does not settle: the balance at each checkpoint is")
    print(f"  the validator's own record. Up to {widest} transactions sit between two")
    print("  checkpoints, so an outflow fully replaced before the next checkpoint")
    print("  would not show up here. This is a bound, not a proof of no outflow.")
    print("")
    if require_monotonic:
        checks.expect_true(
            "no token account's balance fell between any two checkpoints",
            walk["monotonic"], f"{walk['falls']} falls across "
                               f"{len(walk['accounts'])} accounts")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

# Pinned facts. Each was read from the chain once, by hand, and is re-read on
# every self-test. If Raydium changes a fee tier these will fail — which is the
# point: the control is meant to notice.
PIN_CLMM = {"address": "E64NGkDLLCdQ2yFNPcavaKptrEgmiQaNykUuLC1Qgwyp",
            "index": 1, "trade_fee_rate": 2500, "protocol_fee_rate": 120000,
            "fund_fee_rate": 40000, "tick_spacing": 60}
PIN_CPMM = {"address": "D4FPEruKEHrG5TenZ2mpDGEfu1iUvTiqBxvpU8HLBvC2",
            "index": 0, "trade_fee_rate": 2500, "protocol_fee_rate": 120000,
            "fund_fee_rate": 40000, "create_pool_fee": 150_000_000}
RAY_MINT = "4k3Dyjzvzp8eMZWUXbBCjEvwSkkk59S5iCNLY3QrkX6R"
BUYBACK_WALLET = "DdHDoz94o2WJmD9myRobHCwtx1bESpHTd4SSPe6VEZaz"


def self_test(url: str = None) -> int:
    """Prove the thing can fail. A check that cannot fail proves nothing."""
    banner("SELF-TEST — fee_split.py", url)
    results = []

    def control(name, passed, detail=""):
        results.append((name, passed, detail))
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}"
              + (f"  ({detail})" if detail else ""))

    print("Discriminator arithmetic")
    disc = anchor_discriminator("AmmConfig")
    control("sha256('account:AmmConfig')[:8] is daf42168cbcb2b6f",
            disc.hex() == "daf42168cbcb2b6f", disc.hex())
    control("NEGATIVE: a different account name gives a different discriminator",
            anchor_discriminator("AmmConfigX") != disc)

    print("\nPercentage parsing")
    control("'12', '12%' and '12.0' all parse to 12/100",
            parse_percent("12") == parse_percent("12%") == parse_percent("12.0")
            == Fraction(12, 100))
    try:
        parse_percent("a lot")
        control("NEGATIVE: 'a lot' is refused", False)
    except CheckerError:
        control("NEGATIVE: 'a lot' is refused", True)

    print("\nMonotonicity test (pure, no network)")
    control("a rising series reports no fall", series_falls([1, 1, 5, 9]) == [])
    control("NEGATIVE: a series that dips is reported as a fall",
            series_falls([1, 9, 4, 10]) == [1], "index 1 -> 2")

    print("\nCLMM AmmConfig, pinned account")
    try:
        value = rpc("getAccountInfo", [PIN_CLMM["address"], {"encoding": "base64"}],
                    url=url)["value"]
        raw = base64.b64decode(value["data"][0])
        config = decode_clmm_config(PIN_CLMM["address"], raw)
        ok = all(config[k] == PIN_CLMM[k] for k in
                 ("index", "trade_fee_rate", "protocol_fee_rate", "fund_fee_rate",
                  "tick_spacing"))
        control("decodes to the pinned tier (index 1, 0.25%, 12%, 4%)", ok,
                f"protocol {config['protocol_fee_rate']}, fund {config['fund_fee_rate']}")
        control("the 24 trailing padding bytes are zero, as the layout says",
                config["trailing_padding_is_zero"])
        # The dangerous misread is not a wrong discriminator — that is caught
        # for free. It is the right discriminator followed by fields shifted by
        # one byte, which is what an off-by-one in a struct definition looks
        # like. Splice one byte out after the discriminator and require the
        # decode to be refused rather than to produce a plausible number.
        shifted = raw[:8] + raw[9:] + b"\x00"
        try:
            bad = decode_clmm_config("shifted", shifted)
            control("NEGATIVE: right discriminator, fields shifted one byte — refused",
                    False,
                    f"decoded cleanly to protocol_fee_rate={bad['protocol_fee_rate']}")
        except CheckerError as exc:
            control("NEGATIVE: right discriminator, fields shifted one byte — refused",
                    True, str(exc)[:70])
    except CheckerError as exc:
        control("CLMM pinned account", False, str(exc)[:80])

    print("\nCPMM AmmConfig, pinned account")
    try:
        value = rpc("getAccountInfo", [PIN_CPMM["address"], {"encoding": "base64"}],
                    url=url)["value"]
        raw = base64.b64decode(value["data"][0])
        config = decode_cpmm_config(PIN_CPMM["address"], raw)
        ok = all(config[k] == PIN_CPMM[k] for k in
                 ("index", "trade_fee_rate", "protocol_fee_rate", "fund_fee_rate",
                  "create_pool_fee"))
        control("decodes to the pinned tier (index 0, 0.25%, 12%, 4%, 0.15 SOL)", ok,
                f"protocol {config['protocol_fee_rate']}, "
                f"create fee {config['create_pool_fee']}")
    except CheckerError as exc:
        control("CPMM pinned account", False, str(exc)[:80])

    print("\nNEGATIVE: an account that is not an AmmConfig")
    try:
        value = rpc("getAccountInfo", [RAY_MINT, {"encoding": "base64"}],
                    url=url)["value"]
        raw = base64.b64decode(value["data"][0])
        decode_clmm_config(RAY_MINT, raw)
        control("the RAY mint is refused as an AmmConfig", False,
                "it decoded, which it must not")
    except CheckerError as exc:
        control("the RAY mint is refused as an AmmConfig", True, str(exc)[:60])

    print("\nAMM v4 fee struct")
    try:
        good = struct.pack("<8Q", 5, 10000, 25, 10000, 12, 100, 25, 10000)
        fees = decode_v4_fees(good)
        control("a real Fees struct decodes to pnl 12/100 and swap fee 25/10000",
                fees["pnl_numerator"] == 12 and fees["pnl_denominator"] == 100
                and fees["swap_fee_numerator"] == 25)
        control("an all-zero struct is reported uninitialised, not as 0% fees",
                decode_v4_fees(b"\x00" * 64)["initialised"] is False)
        try:
            decode_v4_fees(struct.pack("<8Q", 5, 10000, 25, 10000, 500, 100, 25, 10000))
            control("NEGATIVE: a fee over 100% is refused", False)
        except CheckerError:
            control("NEGATIVE: a fee over 100% is refused", True)
        try:
            decode_v4_fees(b"\x01" * 32)
            control("NEGATIVE: a short slice is refused", False)
        except CheckerError:
            control("NEGATIVE: a short slice is refused", True)
    except CheckerError as exc:
        control("v4 fee struct", False, str(exc)[:80])

    print("\nAMM v4 dataSlice alignment, against the live chain")
    try:
        slice_control = v4_slice_control(url=url)
        control("the sliced 64 bytes equal bytes 128..192 of the whole account",
                slice_control["agrees"], slice_control["pool"])
    except CheckerError as exc:
        control("v4 dataSlice alignment", False, str(exc)[:80])

    print("\nHoldings, two RPC methods on one account")
    try:
        held = holdings(BUYBACK_WALLET, RAY_MINT, url=url)
        control("raw token-account bytes and getTokenAccountBalance agree",
                held["cross_checked_largest"] == held["accounts"][0]["amount"],
                f"{held['total_tokens']:,.2f} RAY")
    except CheckerError as exc:
        control("holdings cross-check", False, str(exc)[:80])

    print("\nNEGATIVE: things that must be refused, not guessed")
    try:
        holdings("not-an-address", RAY_MINT, url=url)
        control("a malformed owner address is refused", False)
    except CheckerError:
        control("a malformed owner address is refused", True)
    try:
        mint_decimals("11111111111111111111111111111111", url=url)
        control("the System Program is refused as a mint", False)
    except CheckerError:
        control("the System Program is refused as a mint", True)

    passed = sum(1 for _, ok, _ in results if ok)
    print(f"\n{passed}/{len(results)} controls passed "
          f"({sum(1 for n, _, _ in results if 'NEGATIVE' in n)} of them negative "
          "controls, which pass only by failing the way they should).")
    return 0 if passed == len(results) else 1


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the fee split a venue advertises against the "
                    "configuration accounts that actually govern it.",
        epilog="Exit 0 = all assertions held, 1 = an assertion is false, "
               "2 = could not check.")
    parser.add_argument("--venue", action="append", default=None,
                        choices=sorted(VENUES) + ["all"],
                        help="which program's fee configuration to read. Repeatable.")
    parser.add_argument("--expect-protocol-share", default=None,
                        help="assert the protocol/buyback share of the TRADING FEE, "
                             "e.g. 12 or 12%%")
    parser.add_argument("--expect-fund-share", default=None,
                        help="assert the fund/treasury share of the trading fee")
    parser.add_argument("--expect-trade-fee", default=None,
                        help="assert the swap fee itself (amm v4 only, where it is "
                             "per pool)")
    parser.add_argument("--expect-create-pool-fee", type=float, default=None,
                        help="assert the pool creation fee, in SOL")
    parser.add_argument("--holds", metavar="MINT", default=None,
                        help="the mint the destination address should hold")
    parser.add_argument("--at", metavar="OWNER", default=None,
                        help="the address said to hold it")
    parser.add_argument("--expect-at-least", type=float, default=None,
                        help="assert the holding is at least this many whole tokens")
    parser.add_argument("--trajectory", type=int, nargs="?", const=200, default=None,
                        metavar="N",
                        help="walk the destination's history at N checkpoints "
                             "(default 200) and report whether the balance ever fell")
    parser.add_argument("--expect-never-fell", action="store_true",
                        help="assert the balance never fell between checkpoints")
    parser.add_argument("--rpc", default=None, help="a Solana RPC endpoint")
    parser.add_argument("--json", default=None, help="write the findings here")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    url = args.rpc or rpc_url()
    if args.self_test:
        return self_test(url)

    venues = args.venue or []
    if "all" in venues:
        venues = sorted(VENUES)
    if not venues and not args.holds:
        parser.error("nothing to do: pass --venue and/or --holds/--at")
    if bool(args.holds) != bool(args.at):
        parser.error("--holds and --at go together")

    banner("FEE SPLIT CHECK", url)
    checks = Checks()
    findings = {"checked_at": utc_now(), "rpc": "<endpoint>", "venues": {},
                "holdings": None, "trajectory": None}
    expect_protocol = (parse_percent(args.expect_protocol_share)
                       if args.expect_protocol_share is not None else None)
    expect_fund = (parse_percent(args.expect_fund_share)
                   if args.expect_fund_share is not None else None)
    expect_trade = (parse_percent(args.expect_trade_fee)
                    if args.expect_trade_fee is not None else None)

    try:
        for venue_key in venues:
            venue = VENUES[venue_key]
            if venue["kind"] == "amm-config":
                census = census_amm_config(venue_key, url=url)
                report_amm_config_census(census, checks, expect_protocol,
                                         expect_fund, args.expect_create_pool_fee)
                findings["venues"][venue_key] = census
            else:
                control = v4_slice_control(url=url)
                census = census_v4_pools(url=url)
                config = v4_config(url=url)
                report_v4_census(census, control, config, checks, expect_protocol,
                                 expect_trade, args.expect_create_pool_fee)
                findings["venues"][venue_key] = {"census": census,
                                                 "slice_control": control,
                                                 "config": config}

        if args.holds:
            held = holdings(args.at, args.holds, url=url)
            report_holdings(held, checks, args.expect_at_least,
                            "DESTINATION HOLDINGS")
            findings["holdings"] = held
            if args.trajectory is not None:
                walk = trajectory(args.at, args.holds, checkpoints=args.trajectory,
                                  url=url)
                report_trajectory(walk, checks, args.expect_never_fell)
                findings["trajectory"] = walk
    except CheckerError as exc:
        print(f"\nCOULD NOT CHECK: {exc}")
        return 2

    checks.print_report()
    if args.json:
        findings["assertions"] = checks.rows
        with open(args.json, "w") as handle:
            json.dump(findings, handle, indent=1, default=str)
        print(f"\nwrote {args.json}")

    print("\nWHAT THIS DOES NOT SETTLE")
    print("-" * 70)
    print("  A rate in a config account is what the program charges. It is not")
    print("  evidence that the collected fee was later spent the way anyone said")
    print("  it would be. These rates are also mutable: the accounts printed above")
    print("  as signers, and each program's compiled-in admin, can change them.")
    return checks.exit_code()


if __name__ == "__main__":
    sys.exit(main())
