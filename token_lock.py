#!/usr/bin/env python3
"""
token_lock.py — check whether locked tokens are actually locked, and by what.

CLAIM CLASS: "our tokens / our liquidity are locked and cannot be released
early" — the unlock date, the amount, who (if anyone) may cancel or transfer
the lock, and whether the program enforcing it is immutable or can be replaced
by an upgrade authority.

RUN: python3 checkers/token_lock.py <LOCK_ADDRESS> --expect-not-cancelable --expect-program-immutable

What this answers
-----------------
"Locked" is three separate claims wearing one word, and they fail in different
ways:

  1. **The schedule.** How much was deposited, when does it unlock, has it
     already been withdrawn? Read from the lock account's own bytes.
  2. **The cancel path.** Can the depositor pull it back? Can the recipient?
     Can it be transferred to someone else, or topped up? These are per-lock
     boolean flags stored in the account. A "lock" with `cancelable_by_sender`
     set is not a lock; it is a promise with a cancel button.
  3. **The enforcing program.** Every lock is only as durable as the code that
     enforces it. On Solana a program with an upgrade authority can be replaced
     with different code by whoever holds that authority. Because the escrow
     token account's authority is a program-derived address — an address with
     no private key, that only this program's code can sign for — replacing the
     code replaces the rules that decide where those tokens go.

Number 3 is the one almost nobody checks, and it is the one that makes the
words "immutable" and "no backdoor" either true or false. `--expect-program-
immutable` asserts it, and fails loudly when the program is upgradeable, naming
the authority that could do it.

**An upgrade authority is not an accusation.** Most Solana programs have one and
it is often the responsible choice — it is how bugs get fixed. This checker
reports a capability, never an intention. What it refuses to do is let the word
"immutable" pass unexamined.

Two modes
---------
  token_lock.py <LOCK_ADDRESS>        decode a lock, and check its program
  token_lock.py --program <PROGRAM>   just the immutability question, for any
                                      Solana program at all

The second mode settles the general claim *"our contract is immutable"* /
*"ownership is renounced"* for any program on the chain, lock or not.

How the layout is trusted
-------------------------
Field offsets are not taken on faith. The lock account records the address of
its own escrow token account; this checker independently re-derives that
address as a program-derived address from the program ID and the lock's own
address, and requires the two to be equal. If the assumed offsets were wrong,
the bytes read at the escrow offset would be something else and the derivation
would not match. That check is a control on the decoder itself and it runs on
every lock.

Exit codes
----------
  0  every assertion held
  1  at least one assertion is false
  2  it could not be checked (network, bad address, not a lock account)
"""

import argparse
import base64
import json
import struct
import sys
from datetime import datetime, timezone

sys.path.insert(0, __file__.rsplit("/", 1)[0])
import _lib as lib  # noqa: E402


MAINNET_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"
BPF_UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"
SPL_TOKEN = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
SPL_TOKEN_2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

# Lock programs this checker can decode, and where the program ID came from.
# Both IDs are published by Streamflow in their own SDK, not read off an
# explorer: https://github.com/streamflow-finance/js-sdk
#   packages/stream/solana/constants.ts  ->  PROGRAM_ID / ALIGNED_UNLOCKS_PROGRAM_ID
KNOWN_LOCK_PROGRAMS = {
    "strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m": "Streamflow protocol (mainnet)",
    "aSTRM2NKoKxNnkmLWk9sz3k74gKBk9t7bpPrTGxMszH": "Streamflow aligned unlocks (mainnet)",
    "HqDGZjaVRXJ9MGRQEw7qDc2rAr6iH1n1kAQdCZaCMfMZ": "Streamflow protocol (devnet/testnet)",
}

# The seed prefix Streamflow uses for both the escrow token account and the
# contract's signing PDA.
STRM_SEED = b"strm"

# Streamflow contract ("TokenStreamData") layout. Every offset below is
# confirmed against the three offsets Streamflow publishes in its own SDK
# (constants.ts): sender=49, recipient=113, mint=177, closed=671. The escrow
# offset is confirmed at runtime by PDA re-derivation, see check_lock().
LOCK_ACCOUNT_LEN = 1104
OFF = {
    "magic": 0,                        # u64
    "version": 8,                      # u8
    "created_at": 9,                   # u64  unix seconds
    "withdrawn_amount": 17,            # u64
    "canceled_at": 25,                 # u64  unix seconds, 0 = not cancelled
    "end_time": 33,                    # u64  unix seconds
    "last_withdrawn_at": 41,           # u64
    "sender": 49,                      # pubkey   <- SDK: STREAM_STRUCT_OFFSET_SENDER
    "sender_tokens": 81,               # pubkey
    "recipient": 113,                  # pubkey   <- SDK: STREAM_STRUCT_OFFSET_RECIPIENT
    "recipient_tokens": 145,           # pubkey
    "mint": 177,                       # pubkey   <- SDK: STREAM_STRUCT_OFFSET_MINT
    "escrow_tokens": 209,              # pubkey
    "streamflow_treasury": 241,        # pubkey
    "streamflow_treasury_tokens": 273,  # pubkey
    "streamflow_fee_total": 305,       # u64
    "streamflow_fee_withdrawn": 313,   # u64
    "streamflow_fee_percent": 321,     # f32
    "partner": 325,                    # pubkey
    "partner_tokens": 357,             # pubkey
    "partner_fee_total": 389,          # u64
    "partner_fee_withdrawn": 397,      # u64
    "partner_fee_percent": 405,        # f32
    "start_time": 409,                 # u64  unix seconds
    "net_amount_deposited": 417,       # u64
    "period": 425,                     # u64  seconds per release step
    "amount_per_period": 433,          # u64
    "cliff": 441,                      # u64  unix seconds
    "cliff_amount": 449,               # u64
    "cancelable_by_sender": 457,       # bool
    "cancelable_by_recipient": 458,    # bool
    "automatic_withdrawal": 459,       # bool
    "transferable_by_sender": 460,     # bool
    "transferable_by_recipient": 461,  # bool
    "can_topup": 462,                  # bool
    "stream_name": 463,                # [u8; 64]
    "withdraw_frequency": 527,         # u64
    "closed": 671,                     # bool     <- SDK: STREAM_STRUCT_OFFSET_CLOSED
}

# A real mainnet lock, captured 2026-08-16, embedded so that the decoder's
# self-test needs no network and cannot drift when the account changes or is
# closed and its rent reclaimed.
#   5VpnWocDjK4DLWbTGD8XZnB6TbBK6VpdfHXYi1QonBKQ
FIXTURE_LOCK_ADDRESS = "5VpnWocDjK4DLWbTGD8XZnB6TbBK6VpdfHXYi1QonBKQ"
FIXTURE_LOCK_PROGRAM = "strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m"
FIXTURE_LOCK_B64 = (
    "BAAAAAAAAAAE/TXzaQAAAAAAAAAAAAAAAAAAAAAAAAAAcd42awAAAAAAAAAAAAAAAHLtGiHP"
    "eO8PBlmfwR5bmcwCWIy1/Z0DWKtBHlpaCFCMLSBlDFhqGrqbcdNuB4Ycg3OOvw27myEpFfWg"
    "rpsfoYVy7Rohz3jvDwZZn8EeW5nMAliMtf2dA1irQR5aWghQjC0gZQxYahq6m3HTbgeGHINz"
    "jr8Nu5shKRX1oK6bH6GFIOOYIdjUTC19XMr33u8Q/v4FYaV2bFEseiu0nWFBTV9WiW+oZ72N"
    "H+m/cOOkppVCyIteTvjJuGPTVPfx823TC0Hl5R1mQ0ba9Ai8PKVNKf8XMsMfSRvbApBNvbh6"
    "jHDC0+iR3QqKV9ETvagepSIntO3PkKApZeQlfGyIsOHStawAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AESGXafX4/xc+N/wzznRKr7OEfOIMdiDmUXuyiXNpA4BumwYFNOPq1L/zq1Pc7AasLLImEF1"
    "BSH/46fKWDvu68YAAAAAAAAAAAAAAAAAAAAAAAAAAHDeNmsAAAAAAEBjUr/GAQABAAAAAAAA"
    "AABAY1K/xgEAcN42awAAAAD/P2NSv8YBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAeAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAaIkJAYCy5g4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)


# --------------------------------------------------------------------------
# decoding
# --------------------------------------------------------------------------

def _u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def _f32(data, off):
    return struct.unpack_from("<f", data, off)[0]


def _pk(data, off):
    return lib.b58encode(data[off:off + 32])


def _ts(value):
    """A unix second count as text, or a plain number when it is out of range."""
    if value == 0:
        return "0 (unset)"
    if not (1_000_000_000 < value < 4_102_444_800):   # ~2001 .. 2100
        return f"{value} (not a plausible unix time)"
    return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def decode_lock(data: bytes) -> dict:
    """Decode a Streamflow contract account from its raw bytes. No network."""
    if len(data) != LOCK_ACCOUNT_LEN:
        raise lib.CheckerError(
            f"this account is {len(data)} bytes; a Streamflow lock is exactly "
            f"{LOCK_ACCOUNT_LEN}. Refusing to decode it as one — a wrong layout "
            f"would produce confident nonsense.")
    out = {}
    for name, off in OFF.items():
        if name == "stream_name":
            out[name] = data[off:off + 64].rstrip(b"\x00").decode("utf-8", "replace")
        elif name in ("version", "cancelable_by_sender", "cancelable_by_recipient",
                      "automatic_withdrawal", "transferable_by_sender",
                      "transferable_by_recipient", "can_topup", "closed"):
            out[name] = data[off]
        elif name in ("streamflow_fee_percent", "partner_fee_percent"):
            out[name] = _f32(data, off)
        elif name in ("sender", "sender_tokens", "recipient", "recipient_tokens",
                      "mint", "escrow_tokens", "streamflow_treasury",
                      "streamflow_treasury_tokens", "partner", "partner_tokens"):
            out[name] = _pk(data, off)
        else:
            out[name] = _u64(data, off)
    return out


def derive_escrow(lock_address: str, program_id: str) -> str:
    """Re-derive the escrow token account address from first principles."""
    seeds = [STRM_SEED, lib.b58decode(lock_address)]
    addr, _bump = lib.find_program_address(seeds, lib.b58decode(program_id))
    return lib.b58encode(addr)


def read_program_authority(program_id: str, url=None) -> dict:
    """Read a program's upgrade authority from the BPF upgradeable loader.

    Works for any Solana program, not just lock programs. Raises rather than
    guessing when the account is not a loader-owned program.
    """
    acct = lib.get_account(program_id, url=url)
    if acct is None:
        raise lib.CheckerError(f"no account exists at {program_id}")
    if acct["owner"] != BPF_UPGRADEABLE_LOADER:
        # A program owned by the original (non-upgradeable) loader really is
        # immutable, and that is a legitimate answer rather than an error.
        if acct.get("executable"):
            return {
                "program": program_id,
                "programdata": None,
                "immutable": True,
                "authority": None,
                "last_deployed_slot": None,
                "loader": acct["owner"],
                "note": ("owned by a non-upgradeable loader, so there is no "
                         "upgrade authority and the code cannot be replaced"),
            }
        raise lib.CheckerError(
            f"{program_id} is not an executable program (owner {acct['owner']})")

    data = acct["data"]
    if len(data) < 36:
        raise lib.CheckerError(
            f"{program_id} is loader-owned but only {len(data)} bytes; expected "
            f"at least 36 for a Program account")
    kind = struct.unpack_from("<I", data, 0)[0]
    if kind != 2:
        raise lib.CheckerError(
            f"{program_id} has loader account type {kind}, expected 2 (Program). "
            f"This is a buffer or programdata account, not a program.")
    programdata = lib.b58encode(data[4:36])

    pd = lib.get_account(programdata, url=url)
    if pd is None:
        raise lib.CheckerError(
            f"the program points at programdata {programdata} but no account "
            f"exists there")
    d = pd["data"]
    if len(d) < 13:
        raise lib.CheckerError(
            f"programdata {programdata} is only {len(d)} bytes; cannot decode")
    kind2 = struct.unpack_from("<I", d, 0)[0]
    if kind2 != 3:
        raise lib.CheckerError(
            f"programdata {programdata} has loader account type {kind2}, "
            f"expected 3 (ProgramData)")
    slot = _u64(d, 4)
    opt = d[12]
    if opt not in (0, 1):
        raise lib.CheckerError(
            f"programdata {programdata} option byte at offset 12 is {opt}; "
            f"an Option<Pubkey> tag must be 0 or 1. Refusing to guess.")
    if opt == 1:
        if len(d) < 45:
            raise lib.CheckerError(
                f"programdata {programdata} claims an upgrade authority but is "
                f"too short to hold one")
        authority = lib.b58encode(d[13:45])
    else:
        authority = None
    return {
        "program": program_id,
        "programdata": programdata,
        "immutable": authority is None,
        "authority": authority,
        "last_deployed_slot": slot,
        "loader": BPF_UPGRADEABLE_LOADER,
        "programdata_len": len(d),
        "note": None,
    }


def upgrade_history(programdata: str, url=None) -> list:
    """Every loader instruction that has ever touched this programdata account.

    Returns newest-last. Classifies each as deploy / upgrade / setAuthority so
    that "N transactions touched it" is never reported as "N upgrades".
    """
    sigs, before = [], None
    while True:
        params = [programdata, {"limit": 1000}]
        if before:
            params[1]["before"] = before
        page = lib.rpc("getSignaturesForAddress", params, url=url)
        if not page:
            break
        sigs += page
        before = page[-1]["signature"]
        if len(page) < 1000:
            break
    sigs = sigs[::-1]
    if not sigs:
        return []
    # Solana's free public endpoint rate-limits getTransaction hard and refuses
    # large batches outright (HTTP 429, "Too many requests for a specific RPC
    # call"). Chunks of 5 get through; the default 25 does not. This is slow on
    # purpose so that the command printed on the site works for a stranger with
    # no API key.
    txs = lib.rpc_batch(
        "getTransaction",
        [[s["signature"], {"encoding": "jsonParsed",
                           "maxSupportedTransactionVersion": 0}] for s in sigs],
        url=url, chunk=5)
    events = []
    for sig, tx in zip(sigs, txs):
        if not tx:
            continue
        msg = tx["transaction"]["message"]
        ixs = list(msg["instructions"])
        for group in tx["meta"].get("innerInstructions") or []:
            ixs += group["instructions"]
        for ix in ixs:
            if ix.get("programId") != BPF_UPGRADEABLE_LOADER:
                continue
            parsed = ix.get("parsed") or {}
            events.append({
                "signature": sig["signature"],
                "block_time": sig.get("blockTime"),
                "type": parsed.get("type", "<unparsed>"),
                "info": parsed.get("info", {}),
                "failed": bool(sig.get("err")),
            })
    return events


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------

def _require_mainnet(checks, url):
    genesis = lib.rpc("getGenesisHash", [], url=url)
    if genesis != MAINNET_GENESIS:
        raise lib.CheckerError(
            f"this endpoint reports genesis hash {genesis}, which is not "
            f"Solana mainnet-beta. Refusing to report a verdict from it.")
    checks.expect("the endpoint really is Solana mainnet-beta (genesis hash)",
                  genesis, MAINNET_GENESIS)


def check_program(program_id, expect_immutable=False, expect_authority=None,
                  show_history=False, url=None, out=sys.stdout) -> tuple:
    """Settle 'this program is immutable' for any Solana program."""
    checks = lib.Checks()
    lib.banner(f"PROGRAM IMMUTABILITY CHECK — {program_id}", url=url, stream=out)
    _require_mainnet(checks, url)

    info = read_program_authority(program_id, url=url)
    label = KNOWN_LOCK_PROGRAMS.get(program_id)
    if label:
        print(f"  known as         {label}", file=out)
    print(f"  loader           {info['loader']}", file=out)
    if info["programdata"]:
        print(f"  programdata      {info['programdata']}", file=out)
        print(f"  last deployed    slot {info['last_deployed_slot']}", file=out)
    if info["immutable"]:
        print("  upgrade authority  NONE — the deployed code cannot be replaced",
              file=out)
    else:
        print(f"  upgrade authority  {info['authority']}", file=out)
        onchain = lib.get_account(info["authority"], url=url)
        offcurve = not lib.is_on_curve(lib.b58decode(info["authority"]))
        kind = ("off-curve (a program-derived address — no private key exists "
                "for it, so some program controls it)" if offcurve
                else "on-curve (a plain keypair — one private key is enough)")
        print(f"                     {kind}", file=out)
        if onchain is not None:
            print(f"                     owner program {onchain['owner']}", file=out)

    events = []
    if show_history and info["programdata"]:
        try:
            events = upgrade_history(info["programdata"], url=url)
        except lib.CheckerError as exc:
            # The immutability answer above is already established and does not
            # depend on the history. Record the gap rather than throwing that
            # away, but never let it look like "no upgrades found".
            checks.blocked("the deploy/upgrade history of this program",
                           f"could not be read: {exc}")
            print(f"\n  UPGRADE HISTORY — NOT READ: {exc}", file=out)
            events = None
    if events:
        counts = {}
        for e in events:
            counts[e["type"]] = counts.get(e["type"], 0) + 1
        print("\n  UPGRADE HISTORY (loader instructions on the programdata account)",
              file=out)
        for e in events:
            when = (datetime.fromtimestamp(e["block_time"], timezone.utc)
                    .strftime("%Y-%m-%d %H:%M") if e["block_time"] else "?")
            extra = ""
            if e["type"] == "setAuthority":
                extra = (f"  {e['info'].get('authority')} -> "
                         f"{e['info'].get('newAuthority')}")
            print(f"    {when}  {e['type']:<22} {e['signature'][:24]}…{extra}",
                  file=out)
        print(f"    totals: {counts}", file=out)

    print("", file=out)
    if expect_immutable:
        checks.expect_true(
            "the program is immutable — no upgrade authority, so nobody can "
            "replace the deployed code",
            info["immutable"],
            "no upgrade authority" if info["immutable"]
            else f"upgrade authority is {info['authority']}")
    if expect_authority is not None:
        want = None if expect_authority.lower() == "none" else expect_authority
        checks.expect("the upgrade authority is exactly the expected account",
                      info["authority"], want)

    print("WHAT THIS CANNOT TELL YOU", file=out)
    print("-" * 70, file=out)
    print("  An upgrade authority is a capability, not an intention. That an", file=out)
    print("  account CAN replace this program's code is not evidence that it", file=out)
    print("  ever has, or ever would. Most Solana programs are upgradeable and", file=out)
    print("  it is frequently the responsible choice.", file=out)
    print("  Equally, 'immutable' here means only that the loader records no", file=out)
    print("  upgrade authority. It says nothing about what the code does — an", file=out)
    print("  immutable program can still contain an admin key in its own state.", file=out)
    return checks, {"program": info, "history": events}


def check_lock(lock_address, data=None, program_id=None,
               expect_not_cancelable=False, expect_program_immutable=False,
               expect_locked_until=None, expect_deposited=None,
               expect_mint=None, url=None, out=sys.stdout, offline=False) -> tuple:
    """Decode one lock and settle claims about it."""
    checks = lib.Checks()
    lib.banner(f"TOKEN LOCK CHECK — {lock_address}", url=url, stream=out)

    if not offline:
        _require_mainnet(checks, url)
        acct = lib.get_account(lock_address, url=url)
        if acct is None:
            raise lib.CheckerError(f"no account exists at {lock_address}")
        data = acct["data"]
        program_id = acct["owner"]
        checks.expect_true(
            "the account is owned by a lock program this checker can decode",
            program_id in KNOWN_LOCK_PROGRAMS,
            f"owner is {program_id}"
            + (f" — {KNOWN_LOCK_PROGRAMS[program_id]}"
               if program_id in KNOWN_LOCK_PROGRAMS else " — UNKNOWN"))
        if program_id not in KNOWN_LOCK_PROGRAMS:
            raise lib.CheckerError(
                f"{lock_address} is owned by {program_id}, which is not a lock "
                f"program this checker knows how to decode. Refusing to guess "
                f"at its layout.")

    lock = decode_lock(data)

    # --- the control on the decoder itself -------------------------------
    derived = derive_escrow(lock_address, program_id)
    layout_ok = derived == lock["escrow_tokens"]
    checks.expect_true(
        "the escrow address stored in the account re-derives as a program "
        "address from the program ID and the lock's own address (proves these "
        "bytes really are laid out where this checker assumes)",
        layout_ok,
        f'PDA ["strm", {lock_address[:8]}…] = {derived}; '
        f'field at byte {OFF["escrow_tokens"]} = {lock["escrow_tokens"]}')
    if not layout_ok:
        raise lib.CheckerError(
            "the escrow field does not match the derived escrow address. Either "
            "this is not the account it claims to be or the layout assumed here "
            "is wrong. Refusing to report any decoded value.")

    dec_hint = ""
    print(f"  program          {program_id}"
          f"  ({KNOWN_LOCK_PROGRAMS.get(program_id, 'unknown')})", file=out)
    print(f"  name             {lock['stream_name']!r}", file=out)
    print(f"  mint             {lock['mint']}", file=out)
    print(f"  depositor        {lock['sender']}", file=out)
    print(f"  beneficiary      {lock['recipient']}", file=out)
    print(f"  escrow (PDA)     {lock['escrow_tokens']}   re-derived above", file=out)
    print("", file=out)
    print(f"  deposited        {lock['net_amount_deposited']} base units{dec_hint}",
          file=out)
    print(f"  withdrawn        {lock['withdrawn_amount']} base units", file=out)
    print(f"  starts           {_ts(lock['start_time'])}", file=out)
    print(f"  cliff            {_ts(lock['cliff'])}  (cliff amount "
          f"{lock['cliff_amount']})", file=out)
    print(f"  fully unlocked   {_ts(lock['end_time'])}", file=out)
    print(f"  release step     every {lock['period']}s, "
          f"{lock['amount_per_period']} base units per step", file=out)
    single = lock["amount_per_period"] >= lock["net_amount_deposited"]
    print(f"  shape            {'single unlock (cliff-style lock)' if single else 'linear vesting'}",
          file=out)
    print(f"  closed           {'yes' if lock['closed'] else 'no'}", file=out)
    print(f"  cancelled at     {_ts(lock['canceled_at'])}", file=out)
    print("", file=out)
    print("  PER-LOCK PERMISSION FLAGS (byte offsets 457-462)", file=out)
    for name in ("cancelable_by_sender", "cancelable_by_recipient",
                 "transferable_by_sender", "transferable_by_recipient",
                 "can_topup", "automatic_withdrawal"):
        print(f"    [{OFF[name]}] {name:<26} {'YES' if lock[name] else 'no'}",
              file=out)
    print("", file=out)

    # --- escrow authority: who can actually move the tokens --------------
    escrow_state = None
    if not offline:
        resp = lib.rpc("getAccountInfo",
                       [lock["escrow_tokens"], {"encoding": "jsonParsed"}],
                       url=url)
        escrow_state = (resp or {}).get("value")
        if escrow_state is None:
            checks.blocked("the escrow token account's authority is the escrow "
                           "PDA itself, so only the program's code can sign for it",
                           "the escrow token account no longer exists (a closed "
                           "lock has its escrow reclaimed)")
        else:
            info = escrow_state["data"]["parsed"]["info"]
            authority = info["owner"]
            checks.expect(
                "the escrow token account's authority is the escrow PDA itself, "
                "so no private key can move the locked tokens and only the "
                "program's own code can",
                authority, lock["escrow_tokens"])
            checks.expect("the escrow token account holds the same mint as the lock",
                          info["mint"], lock["mint"])
            print(f"  escrow balance   {info['tokenAmount']['amount']} base units "
                  f"({info['tokenAmount']['decimals']} decimals)", file=out)
            print(f"  escrow authority {authority}", file=out)
            print("", file=out)

    checks.expect_true(
        "the escrow address is off the ed25519 curve, so no private key for it "
        "can exist",
        not lib.is_on_curve(lib.b58decode(lock["escrow_tokens"])),
        "derived address is not a valid ed25519 point")

    # --- the enforcing program -------------------------------------------
    prog = None
    if not offline:
        prog = read_program_authority(program_id, url=url)
        print("  THE PROGRAM THAT ENFORCES THIS LOCK", file=out)
        if prog["immutable"]:
            print("    upgrade authority  NONE — the rules enforcing this lock "
                  "cannot be changed", file=out)
        else:
            print(f"    upgrade authority  {prog['authority']}", file=out)
            print("    Whoever controls that account can replace this program's",
                  file=out)
            print("    code. The escrow above is signed for by program code, so",
                  file=out)
            print("    replacing the code replaces the rules deciding where these",
                  file=out)
            print("    tokens go. This is a capability, not an accusation.", file=out)
        print("", file=out)

    # --- assertions -------------------------------------------------------
    if expect_not_cancelable:
        neither = not lock["cancelable_by_sender"] and not lock["cancelable_by_recipient"]
        checks.expect_true(
            "neither party can cancel this lock early (both cancelable flags clear)",
            neither,
            f"cancelable_by_sender={bool(lock['cancelable_by_sender'])}, "
            f"cancelable_by_recipient={bool(lock['cancelable_by_recipient'])}")
    if expect_program_immutable:
        if prog is None:
            checks.blocked("the program enforcing this lock is immutable",
                           "not checked in offline mode")
        else:
            checks.expect_true(
                "the program enforcing this lock is immutable — no upgrade "
                "authority, so the rules cannot be replaced",
                prog["immutable"],
                "no upgrade authority" if prog["immutable"]
                else f"upgrade authority is {prog['authority']}")
    if expect_locked_until:
        want = int(datetime.strptime(expect_locked_until, "%Y-%m-%d")
                   .replace(tzinfo=timezone.utc).timestamp())
        checks.expect_true(
            f"nothing is fully unlocked before {expect_locked_until}",
            lock["end_time"] >= want,
            f"end_time is {_ts(lock['end_time'])}")
    if expect_deposited is not None:
        checks.expect("the amount deposited into the lock",
                      lock["net_amount_deposited"], int(expect_deposited))
    if expect_mint is not None:
        checks.expect("the locked token's mint", lock["mint"], expect_mint)

    print("WHAT THIS CANNOT TELL YOU", file=out)
    print("-" * 70, file=out)
    print("  The permission flags above are the values the account stores. That", file=out)
    print("  the program HONOURS them is a property of its compiled code, which", file=out)
    print("  is not decoded here. This checker reads state, not bytecode.", file=out)
    print("  If the program is upgradeable, both of those become promises about", file=out)
    print("  the code that happens to be deployed right now.", file=out)
    return checks, {"lock": lock, "program": prog, "derived_escrow": derived}


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

def self_test(url=None) -> int:
    """Positive and negative controls. A check that cannot fail proves nothing."""
    import io
    passed = failed = negative = 0

    def record(name, ok, is_negative=False):
        nonlocal passed, failed, negative
        if is_negative:
            negative += 1
        if ok:
            passed += 1
            print(f"  [ ok ] {name}")
        else:
            failed += 1
            print(f"  [FAIL] {name}")

    null = io.StringIO()
    print("SELF-TEST — token_lock.py")
    print("=" * 70)

    # ---- offline decoder controls (no network) --------------------------
    print("\nOffline decoder, against an embedded real mainnet lock:")
    data = base64.b64decode(FIXTURE_LOCK_B64)
    record("the fixture is exactly 1104 bytes", len(data) == LOCK_ACCOUNT_LEN)
    lock = decode_lock(data)

    derived = derive_escrow(FIXTURE_LOCK_ADDRESS, FIXTURE_LOCK_PROGRAM)
    record("the escrow field re-derives as a PDA of the program (layout control)",
           derived == lock["escrow_tokens"])

    record("decodes the deposited amount (500,000,000 tokens at 6 decimals)",
           lock["net_amount_deposited"] == 500_000_000_000_000)
    record("decodes the unlock date as 2026-12-31",
           datetime.fromtimestamp(lock["end_time"], timezone.utc)
           .strftime("%Y-%m-%d") == "2026-12-31")
    record("decodes this lock as non-cancelable by either party",
           lock["cancelable_by_sender"] == 0 and lock["cancelable_by_recipient"] == 0)
    record("decodes it as a single-unlock lock, not linear vesting",
           lock["amount_per_period"] >= lock["net_amount_deposited"])

    # NEGATIVE: a truncated account must raise, not decode
    try:
        decode_lock(data[:1000])
        record("NEGATIVE: a truncated lock account is rejected", False, True)
    except lib.CheckerError:
        record("NEGATIVE: a truncated lock account is rejected", True, True)

    # NEGATIVE: an over-long account must raise too
    try:
        decode_lock(data + b"\x00" * 8)
        record("NEGATIVE: an over-long account is rejected", False, True)
    except lib.CheckerError:
        record("NEGATIVE: an over-long account is rejected", True, True)

    # NEGATIVE: flip cancelable_by_sender and confirm the checker notices
    mutated = bytearray(data)
    mutated[OFF["cancelable_by_sender"]] = 1
    m = decode_lock(bytes(mutated))
    record("NEGATIVE: a lock with cancelable_by_sender set decodes as cancelable",
           m["cancelable_by_sender"] == 1, True)
    c, _ = check_lock(FIXTURE_LOCK_ADDRESS, data=bytes(mutated),
                      program_id=FIXTURE_LOCK_PROGRAM, expect_not_cancelable=True,
                      offline=True, out=null)
    record("NEGATIVE: --expect-not-cancelable FAILS on that mutated lock",
           c.any_failed, True)

    # POSITIVE: the same assertion passes on the real bytes
    c, _ = check_lock(FIXTURE_LOCK_ADDRESS, data=data,
                      program_id=FIXTURE_LOCK_PROGRAM, expect_not_cancelable=True,
                      offline=True, out=null)
    record("--expect-not-cancelable passes on the real lock", not c.any_failed)

    # NEGATIVE: corrupt the escrow field; the layout control must catch it
    mutated = bytearray(data)
    mutated[OFF["escrow_tokens"]] ^= 0xFF
    try:
        check_lock(FIXTURE_LOCK_ADDRESS, data=bytes(mutated),
                   program_id=FIXTURE_LOCK_PROGRAM, offline=True, out=null)
        record("NEGATIVE: a tampered escrow field is caught by the PDA control",
               False, True)
    except lib.CheckerError:
        record("NEGATIVE: a tampered escrow field is caught by the PDA control",
               True, True)

    # NEGATIVE: right bytes, wrong address -> derivation must not match
    try:
        check_lock("11111111111111111111111111111111", data=data,
                   program_id=FIXTURE_LOCK_PROGRAM, offline=True, out=null)
        record("NEGATIVE: the same bytes under a different address are rejected",
               False, True)
    except lib.CheckerError:
        record("NEGATIVE: the same bytes under a different address are rejected",
               True, True)

    # NEGATIVE: wrong expectations must fail
    c, _ = check_lock(FIXTURE_LOCK_ADDRESS, data=data,
                      program_id=FIXTURE_LOCK_PROGRAM,
                      expect_deposited=1, offline=True, out=null)
    record("NEGATIVE: a wrong --expect-deposited fails", c.any_failed, True)
    c, _ = check_lock(FIXTURE_LOCK_ADDRESS, data=data,
                      program_id=FIXTURE_LOCK_PROGRAM,
                      expect_mint="So11111111111111111111111111111111111111112",
                      offline=True, out=null)
    record("NEGATIVE: a wrong --expect-mint fails", c.any_failed, True)
    c, _ = check_lock(FIXTURE_LOCK_ADDRESS, data=data,
                      program_id=FIXTURE_LOCK_PROGRAM,
                      expect_locked_until="2030-01-01", offline=True, out=null)
    record("NEGATIVE: --expect-locked-until beyond the real unlock date fails",
           c.any_failed, True)
    c, _ = check_lock(FIXTURE_LOCK_ADDRESS, data=data,
                      program_id=FIXTURE_LOCK_PROGRAM,
                      expect_locked_until="2026-01-01", offline=True, out=null)
    record("--expect-locked-until before the real unlock date passes",
           not c.any_failed)

    # ---- network controls -------------------------------------------------
    print("\nProgram immutability, against the live chain:")
    try:
        # POSITIVE CONTROL: a program everyone agrees is immutable.
        c, res = check_program(SPL_TOKEN, expect_immutable=True, url=url, out=null)
        record("the SPL Token program reads as immutable (positive control)",
               not c.any_failed and res["program"]["immutable"])

        # NEGATIVE CONTROL: assert immutability of a program that is not.
        c, res = check_program(FIXTURE_LOCK_PROGRAM, expect_immutable=True,
                               url=url, out=null)
        record("NEGATIVE: --expect-program-immutable FAILS on the Streamflow "
               "program", c.any_failed and not res["program"]["immutable"], True)

        # The authority equality assertion, both directions.
        auth = res["program"]["authority"]
        c, _ = check_program(FIXTURE_LOCK_PROGRAM, expect_authority=auth,
                             url=url, out=null)
        record("--expect-upgrade-authority passes on the real authority",
               not c.any_failed)
        c, _ = check_program(FIXTURE_LOCK_PROGRAM, expect_authority="none",
                             url=url, out=null)
        record("NEGATIVE: --expect-upgrade-authority none FAILS when one is set",
               c.any_failed, True)

        # NEGATIVE: a non-program account must raise, not return a clean answer.
        try:
            read_program_authority(SPL_TOKEN_2022 and
                                   "So11111111111111111111111111111111111111112",
                                   url=url)
            record("NEGATIVE: a token mint is rejected as a program", False, True)
        except lib.CheckerError:
            record("NEGATIVE: a token mint is rejected as a program", True, True)

        # NEGATIVE: a nonexistent account must raise.
        try:
            read_program_authority("11111111111111111111111111111112", url=url)
            record("NEGATIVE: a nonexistent program is rejected", False, True)
        except lib.CheckerError:
            record("NEGATIVE: a nonexistent program is rejected", True, True)

    except lib.CheckerError as exc:
        print(f"\n  network controls could not run: {exc}")
        print("  (the offline controls above still ran)")
        return 2

    print("\n" + "-" * 70)
    print(f"{passed} controls passed, {failed} failed, "
          f"{negative} of them negative controls.")
    if failed:
        print("SELF-TEST FAILED — do not believe this checker's verdicts.")
        return 1
    print("Self-test passed. The negative controls confirm it can fail.")
    return 0


# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check whether locked tokens are actually locked, and by "
                    "what program.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("address", nargs="?",
                        help="the lock/contract address (base58)")
    parser.add_argument("--program", metavar="PROGRAM_ID",
                        help="skip the lock and just ask whether this program "
                             "is immutable. Works for any Solana program.")
    parser.add_argument("--expect-not-cancelable", action="store_true",
                        help="assert neither party can cancel the lock early")
    parser.add_argument("--expect-program-immutable", action="store_true",
                        help="assert the enforcing program has no upgrade authority")
    parser.add_argument("--expect-upgrade-authority", metavar="NONE|ADDRESS",
                        help="assert the program's upgrade authority is exactly this")
    parser.add_argument("--expect-locked-until", metavar="YYYY-MM-DD",
                        help="assert nothing is fully unlocked before this date")
    parser.add_argument("--expect-deposited", metavar="N",
                        help="assert the deposited amount in base units")
    parser.add_argument("--expect-mint", metavar="ADDRESS",
                        help="assert the locked token's mint")
    parser.add_argument("--upgrade-history", action="store_true",
                        help="list every deploy/upgrade/authority change")
    parser.add_argument("--rpc", metavar="URL", help="a Solana RPC endpoint")
    parser.add_argument("--json", metavar="PATH", help="write the facts as JSON")
    parser.add_argument("--self-test", action="store_true",
                        help="run the controls, including negative ones")
    args = parser.parse_args()

    url = args.rpc or lib.rpc_url()

    if args.self_test:
        return self_test(url=url)

    if not args.address and not args.program:
        parser.print_help()
        print("\nGive a lock address, or --program <ID>, or --self-test.")
        return 2

    try:
        if args.program:
            checks, facts = check_program(
                args.program,
                expect_immutable=args.expect_program_immutable,
                expect_authority=args.expect_upgrade_authority,
                show_history=args.upgrade_history, url=url)
        else:
            if not lib.is_valid_pubkey(args.address):
                raise lib.CheckerError(f"{args.address!r} is not a valid address")
            checks, facts = check_lock(
                args.address,
                expect_not_cancelable=args.expect_not_cancelable,
                expect_program_immutable=args.expect_program_immutable,
                expect_locked_until=args.expect_locked_until,
                expect_deposited=args.expect_deposited,
                expect_mint=args.expect_mint, url=url)
            if args.upgrade_history and facts.get("program"):
                facts["history"] = upgrade_history(
                    facts["program"]["programdata"], url=url)
    except lib.CheckerError as exc:
        print(f"\nCOULD NOT CHECK: {exc}", file=sys.stderr)
        return 2

    checks.print_report()

    if args.json:
        with open(args.json, "w") as handle:
            json.dump({"checked_at": lib.utc_now(), "facts": facts,
                       "assertions": checks.rows}, handle, indent=2, default=str)
        print(f"\nfacts written to {args.json}")

    if checks.any_failed:
        print("\nRESULT: at least one assertion is FALSE. See the FAIL lines above.")
        return 1
    if checks.any_blocked:
        print("\nRESULT: something could not be checked. See NOT CHECKED above.")
        return 2
    if not checks.assertions:
        print("\nRESULT: report only — no assertion was made, so nothing was settled.")
        return 0
    print("\nRESULT: every assertion holds.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
