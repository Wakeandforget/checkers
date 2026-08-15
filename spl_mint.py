#!/usr/bin/env python3
"""
spl_mint.py — check the supply and the authorities of an SPL token mint.

CLAIM CLASS: "there are N tokens and there will never be more" — total supply,
decimals, mint authority (can anyone create more?), freeze authority (can
anyone freeze your balance?), and Token-2022 extensions, decoded from the raw
bytes of a Solana mint account.

RUN: python3 checkers/spl_mint.py <MINT_ADDRESS> --expect-max-supply 10000000000 --expect-mint-authority none

What this answers
-----------------
A project says "the total supply is 10 billion". That is two different claims
wearing one sentence, and they fail in different ways:

  * how many tokens exist RIGHT NOW      (the `supply` field, scaled by `decimals`)
  * whether that number can ever change  (the `mintAuthority` field)

Check them with the right flag. `--expect-supply` asserts an exact present-day
count; `--expect-max-supply` asserts a ceiling plus the unset mint authority
that makes the ceiling binding. For any token that burns, an exact count is
false the moment the next burn lands, so a published `--expect-supply` command
stops reproducing within days. A ceiling survives every burn. Use
`--expect-supply` only when the claim really is about an exact figure — and
expect it to go stale, which is itself a finding worth reporting.

A ceiling on a token whose mint authority is still SET is not a cap at all,
and `--expect-max-supply` fails such a claim even when the supply is far below
the ceiling. There is a negative control for exactly that (USDC).

The second is the one that matters and the one almost nobody looks at. A mint
whose authority is null is capped by the chain: no key exists that can raise
the supply, ever. A mint whose authority is still set is capped by a promise —
the holder of that one account can mint as much as they like, in one
transaction, without asking anyone. Both mints show the same "total supply"
number on every price site.

The same goes for the freeze authority: if it is set, the holder can freeze any
token account holding this token, making the balance unspendable.

Token-2022 mints can carry extensions — a permanent delegate that can move
anyone's tokens, a transfer hook, a mint close authority. Those are decoded and
listed too, because a claim about supply means much less when a permanent
delegate exists.

Everything below is decoded from the account bytes with the offsets written
out, so a reader can repeat the decode by hand. No SDK, no explorer API, no
credentials.

Exit codes
----------
  0  every assertion held
  1  at least one assertion is false
  2  it could not be checked (network, bad address, not a mint account)
"""

import argparse
import json
import sys
from pathlib import Path

# Allow both "python3 checkers/spl_mint.py" and "python3 -m checkers.spl_mint"
# to find _lib.py, whichever directory the reader happens to be standing in.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _lib as lib  # noqa: E402

# ---------------------------------------------------------------------------
# Facts about the token programs themselves
# ---------------------------------------------------------------------------

# The original SPL Token program. Owns the great majority of mints on Solana.
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

# Token-2022: a newer, separate program with the same 82-byte base layout
# followed by an extension area. A mint owned by this program is NOT the same
# kind of object and can do things the original cannot.
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"

# The base Mint layout is exactly 82 bytes, in this order:
#
#   offset  size  field
#   ------  ----  -----------------------------------------------------------
#      0      4   mintAuthority option tag   (u32 little-endian: 0 = none, 1 = set)
#      4     32   mintAuthority pubkey       (all zeroes and ignored when tag = 0)
#     36      8   supply                     (u64 little-endian, in base units)
#     44      1   decimals
#     45      1   isInitialized              (0 = no, 1 = yes)
#     46      4   freezeAuthority option tag (u32 little-endian)
#     50     32   freezeAuthority pubkey
#
# Note the option tag is FOUR bytes here, not the single byte Borsh uses
# elsewhere. This is the C-style `COption` of the SPL token program. Reading it
# as one byte would shift every field after it by three and produce a decode
# that looks plausible and is wrong.
MINT_LEN = 82

# In a Token-2022 account with extensions, byte 82 is an account-type tag.
ACCOUNT_TYPE_MINT = 1

# Token-2022 extension type ids, from the program's own TLV enum. The list is
# not exhaustive on purpose: an id this script does not recognise is reported
# as UNKNOWN rather than skipped, because an unrecognised power is exactly the
# thing a reader needs told about.
EXTENSION_NAMES = {
    0: "Uninitialized",
    1: "TransferFeeConfig",
    2: "TransferFeeAmount",
    3: "MintCloseAuthority",
    4: "ConfidentialTransferMint",
    5: "ConfidentialTransferAccount",
    6: "DefaultAccountState",
    7: "ImmutableOwner",
    8: "MemoTransfer",
    9: "NonTransferable",
    10: "InterestBearingConfig",
    11: "CpiGuard",
    12: "PermanentDelegate",
    13: "NonTransferableAccount",
    14: "TransferHook",
    15: "TransferHookAccount",
    16: "ConfidentialTransferFeeConfig",
    17: "ConfidentialTransferFeeAmount",
    18: "MetadataPointer",
    19: "TokenMetadata",
    20: "GroupPointer",
    21: "TokenGroup",
    22: "GroupMemberPointer",
    23: "TokenGroupMember",
}

# Extensions that hand somebody a power over tokens they do not hold, or over
# transfers they are not party to. Flagged loudly, because a supply claim about
# a mint with a permanent delegate is not the claim the reader thinks it is.
POWERFUL_EXTENSIONS = {1, 3, 6, 9, 10, 12, 14}


def decode_mint(data: bytes) -> dict:
    """Decode an SPL Mint account from its raw bytes.

    Reads the 82-byte base layout in order, then, if the account is longer,
    the Token-2022 extension area. Cursor refuses to read past the end of the
    data, so a wrong guess about the layout raises instead of inventing a
    number.
    """
    if len(data) < MINT_LEN:
        raise lib.CheckerError(
            f"this account is {len(data)} bytes; an SPL mint is at least "
            f"{MINT_LEN}. This is not a mint account."
        )

    cursor = lib.Cursor(data, label="Mint")

    mint_authority_tag = cursor.u32()
    mint_authority_raw = cursor.take(32)
    supply = cursor.u64()
    decimals = cursor.u8()
    is_initialized = cursor.u8()
    freeze_authority_tag = cursor.u32()
    freeze_authority_raw = cursor.take(32)

    for name, tag in (("mintAuthority", mint_authority_tag),
                      ("freezeAuthority", freeze_authority_tag)):
        if tag not in (0, 1):
            raise lib.CheckerError(
                f"the {name} option tag reads as {tag}, but a COption tag is "
                "always 0 or 1. These bytes are not an SPL mint."
            )

    if is_initialized not in (0, 1):
        raise lib.CheckerError(
            f"isInitialized reads as {is_initialized} at offset 45, but it is a "
            "boolean and must be 0 or 1. These bytes are not an SPL mint."
        )
    if decimals > 18:
        raise lib.CheckerError(
            f"decimals reads as {decimals}, which the token program does not "
            "allow (maximum 9 in practice). These bytes are not an SPL mint."
        )

    decoded = {
        "mintAuthority": lib.b58encode(mint_authority_raw) if mint_authority_tag else None,
        "supplyBaseUnits": supply,
        "decimals": decimals,
        "isInitialized": bool(is_initialized),
        "freezeAuthority": lib.b58encode(freeze_authority_raw) if freeze_authority_tag else None,
        "extensions": [],
        "accountTypeByte": None,
    }

    # --- the Token-2022 extension area, if there is one --------------------
    # Layout after the 82 base bytes: one account-type byte, then a run of
    # TLV records: 2-byte type id, 2-byte length, then that many bytes.
    if len(data) > MINT_LEN:
        account_type = data[MINT_LEN]
        decoded["accountTypeByte"] = account_type
        if account_type != ACCOUNT_TYPE_MINT:
            raise lib.CheckerError(
                f"this account is {len(data)} bytes and its account-type byte at "
                f"offset {MINT_LEN} is {account_type}, not {ACCOUNT_TYPE_MINT} "
                "(Mint). It is a longer account that is not a mint — most likely "
                "a token account or a multisig."
            )
        offset = MINT_LEN + 1
        while offset + 4 <= len(data):
            type_id = int.from_bytes(data[offset:offset + 2], "little")
            length = int.from_bytes(data[offset + 2:offset + 4], "little")
            offset += 4
            if type_id == 0 and length == 0:
                break  # zero padding at the end of the allocated space
            if offset + length > len(data):
                raise lib.CheckerError(
                    f"extension {type_id} at offset {offset - 4} claims {length} "
                    f"bytes but only {len(data) - offset} remain. The extension "
                    "area is malformed and nothing after it can be trusted."
                )
            decoded["extensions"].append({
                "id": type_id,
                "name": EXTENSION_NAMES.get(type_id, f"UNKNOWN({type_id})"),
                "bytes": length,
                "offset": offset - 4,
                "powerful": type_id in POWERFUL_EXTENSIONS or type_id not in EXTENSION_NAMES,
            })
            offset += length

    return decoded


BPF_UPGRADEABLE_LOADER = "BPFLoaderUpgradeab1e11111111111111111111111"

# UpgradeableLoaderState is a Borsh enum. The variant index is a 4-byte tag.
LOADER_STATE_PROGRAM = 2       # then 32 bytes: the ProgramData address
LOADER_STATE_PROGRAM_DATA = 3  # then u64 slot, then COption<Pubkey> upgrade authority


def program_upgrade_authority(program_id: str, url=None) -> dict:
    """Who, if anyone, can replace the code of a Solana program.

    This matters here and is usually left out. "The mint authority is null, so
    the supply can never rise" is a statement about what the token program
    does. If somebody can replace the token program, that guarantee is only as
    good as their restraint. So the guarantee is only complete when the program
    is *also* immutable, and this works that out rather than assuming it.

    Returns {"upgradeAuthority": address or None, "programDataAddress",
    "lastDeployedSlot"}. Raises if the account is not an upgradeable program.
    """
    account = lib.get_account(program_id, url=url)

    if account["owner"] != BPF_UPGRADEABLE_LOADER:
        # Programs under the older loaders cannot be upgraded at all.
        if account["executable"]:
            return {"upgradeAuthority": None, "programDataAddress": None,
                    "lastDeployedSlot": None,
                    "note": f"deployed under {account['owner']}, a "
                            "non-upgradeable loader"}
        raise lib.CheckerError(f"{program_id} is not an executable program account")

    tag = int.from_bytes(account["data"][:4], "little")
    if tag != LOADER_STATE_PROGRAM or len(account["data"]) < 36:
        raise lib.CheckerError(
            f"{program_id}: expected an UpgradeableLoaderState::Program record "
            f"(tag {LOADER_STATE_PROGRAM}), found tag {tag} in {len(account['data'])} bytes"
        )
    program_data_address = lib.b58encode(account["data"][4:36])

    data_account = lib.get_account(program_data_address, url=url)
    data = data_account["data"]
    tag2 = int.from_bytes(data[:4], "little")
    if tag2 != LOADER_STATE_PROGRAM_DATA or len(data) < 45:
        raise lib.CheckerError(
            f"{program_data_address}: expected an "
            f"UpgradeableLoaderState::ProgramData record (tag "
            f"{LOADER_STATE_PROGRAM_DATA}), found tag {tag2}"
        )
    slot = int.from_bytes(data[4:12], "little")
    option = data[12]
    if option not in (0, 1):
        raise lib.CheckerError(
            f"{program_data_address}: the upgrade-authority option byte at "
            f"offset 12 is {option}, which is neither 0 nor 1"
        )
    return {
        "upgradeAuthority": lib.b58encode(data[13:45]) if option == 1 else None,
        "programDataAddress": program_data_address,
        "lastDeployedSlot": slot,
        "note": None,
    }


def scale(base_units: int, decimals: int) -> str:
    """Turn a raw u64 supply into whole tokens, exactly, without floats.

    Floating point would quietly round 9,999,999,999.999999 to 10,000,000,000,
    which is precisely the difference this checker exists to catch. So the
    arithmetic is integer arithmetic and the result is a string.
    """
    if decimals == 0:
        return str(base_units)
    whole, fraction = divmod(base_units, 10 ** decimals)
    return f"{whole:,}.{fraction:0{decimals}d}"


def parse_whole_tokens(text: str, decimals: int) -> int:
    """Turn a claimed human-readable amount into base units, exactly.

    Accepts "10000000000", "10,000,000,000" and "10000000000.5". Raises on
    anything with more decimal places than the mint has, because such a claim
    cannot be represented and silently truncating it would fake a match.
    """
    cleaned = text.replace(",", "").replace("_", "").strip()
    if not cleaned:
        raise lib.CheckerError("empty amount")
    negative = cleaned.startswith("-")
    if negative:
        raise lib.CheckerError(f"{text!r} is negative; a supply cannot be")
    if "." in cleaned:
        whole_part, fraction_part = cleaned.split(".", 1)
    else:
        whole_part, fraction_part = cleaned, ""
    if not whole_part.isdigit() or (fraction_part and not fraction_part.isdigit()):
        raise lib.CheckerError(f"{text!r} is not a number")
    if len(fraction_part) > decimals:
        raise lib.CheckerError(
            f"{text!r} has {len(fraction_part)} decimal places but this mint has "
            f"only {decimals}. That amount cannot exist."
        )
    fraction_part = fraction_part.ljust(decimals, "0")
    return int(whole_part) * (10 ** decimals) + int(fraction_part or "0")


def describe_authority(address, what: str) -> str:
    """A readable line for an authority that may or may not be set."""
    if address is None:
        return f"none — no key can {what}, ever. The chain enforces this."
    return f"{address}"


# ---------------------------------------------------------------------------
# The check itself
# ---------------------------------------------------------------------------


def check(address, expect_supply=None, expect_decimals=None,
          expect_mint_authority=None, expect_freeze_authority=None,
          expect_max_supply=None, url=None, quiet=False):
    """Run the whole check. Returns (Checks, facts-dict).

    `expect_mint_authority` and `expect_freeze_authority` take the literal
    string "none" to assert the authority is unset, or an address to assert it
    is exactly that account.

    `expect_supply` asserts an exact present-day figure. `expect_max_supply`
    asserts a ceiling instead — see the note above the assertion below for why
    the two are not interchangeable.

    Raises CheckerError if it could not get far enough to assert anything —
    the caller turns that into exit code 2, never into a pass.
    """
    out = sys.stderr if quiet else sys.stdout
    checks = lib.Checks()

    if not quiet:
        lib.banner(f"SPL MINT CHECK — {address}", url=url, stream=out)

    # --- 1. fetch and confirm what kind of account this is ------------------
    account = lib.get_account(address, url=url)
    owner = account["owner"]

    if owner not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        # Decoding foreign bytes with the mint layout would produce a supply
        # figure that looks like data. Stop here and say why.
        raise lib.CheckerError(
            f"{address} is owned by {owner}, which is neither the SPL Token "
            f"program ({TOKEN_PROGRAM}) nor Token-2022 ({TOKEN_2022_PROGRAM}). "
            "This is not a token mint."
        )
    program_name = "SPL Token" if owner == TOKEN_PROGRAM else "Token-2022"
    checks.expect_true(
        "the account is owned by a token program, so it can be a mint at all",
        True,
        f"owner is {owner} ({program_name})",
    )

    mint = decode_mint(account["data"])

    if not mint["isInitialized"]:
        raise lib.CheckerError(
            f"the mint at {address} is not initialised. Its supply field means "
            "nothing."
        )

    supply_human = scale(mint["supplyBaseUnits"], mint["decimals"])
    mint_authority = mint["mintAuthority"]
    freeze_authority = mint["freezeAuthority"]

    # An unset mint authority is a promise kept by the token program. So ask
    # the next question, which almost nobody asks: who can rewrite the token
    # program? A "could not check" here is recorded as blocked, not skipped.
    try:
        loader = program_upgrade_authority(owner, url=url)
    except lib.CheckerError as exc:
        loader = None
        checks.blocked(
            "whether the token program itself can be replaced",
            f"could not read the loader records for {owner}: {exc}",
        )
    else:
        checks.observe("token program upgrade authority", loader["upgradeAuthority"])

    # --- 2. report the facts -----------------------------------------------
    if not quiet:
        print(f"  program            {owner}  ({program_name})", file=out)
        print(f"  supply             {supply_human} tokens", file=out)
        print(f"                     = {mint['supplyBaseUnits']} base units "
              f"at {mint['decimals']} decimals", file=out)
        print(f"  mint authority     {describe_authority(mint_authority, 'create more of this token')}",
              file=out)
        if mint_authority is not None:
            print("                     ^ THIS ACCOUNT CAN CREATE MORE TOKENS AT WILL.",
                  file=out)
            on_curve = lib.is_on_curve(lib.b58decode(mint_authority))
            print(f"                       It is {'an ordinary address — a private key for it can exist' if on_curve else 'off the ed25519 curve — a program-derived address, so no private key exists and only a program can sign for it'}.",
                  file=out)
        print(f"  freeze authority   {describe_authority(freeze_authority, 'freeze a holder’s balance')}",
              file=out)
        if freeze_authority is not None:
            print("                     ^ THIS ACCOUNT CAN FREEZE ANY HOLDER'S BALANCE.",
                  file=out)
        print(f"  account            {len(account['data'])} bytes, "
              f"{account['lamports']} lamports of rent", file=out)
        if loader is None:
            print("  token program      COULD NOT CHECK whether the program itself "
                  "can be replaced", file=out)
        elif loader["upgradeAuthority"] is None:
            print("  token program      IMMUTABLE — its upgrade authority is unset, so "
                  "the rules", file=out)
            print("                     above cannot be rewritten by anyone", file=out)
        else:
            print(f"  token program      UPGRADEABLE by {loader['upgradeAuthority']}",
                  file=out)
            print("                     ^ THAT ACCOUNT CAN REPLACE THE CODE THAT "
                  "ENFORCES EVERYTHING", file=out)
            print("                       ABOVE, INCLUDING THE SUPPLY CAP.", file=out)
        if mint["extensions"]:
            print("", file=out)
            print("  TOKEN-2022 EXTENSIONS", file=out)
            for ext in mint["extensions"]:
                flag = "  <-- gives someone a power over other people's tokens" \
                    if ext["powerful"] else ""
                print(f"    id {ext['id']:>3}  {ext['name']:<28} "
                      f"{ext['bytes']} bytes at offset {ext['offset']}{flag}",
                      file=out)
        print("", file=out)
        print("  RAW BYTES OF THE BASE MINT LAYOUT (decode it yourself)", file=out)
        raw82 = account["data"][:MINT_LEN]
        for start in range(0, MINT_LEN, 16):
            chunk = raw82[start:start + 16]
            print(f"    {start:>3}: {chunk.hex()}", file=out)
        print("", file=out)

    # The native mint is a trap. Wrapping SOL does not call MintTo — the token
    # program refuses MintTo and Burn against native accounts outright
    # (TokenError::NativeNotSupported, processor.rs lines 537 and 604), so the
    # native mint's supply field is never written and reads 0 forever. Wrapped
    # SOL plainly exists; the field just does not track it. Any supply or
    # ceiling assertion against this mint is therefore meaningless, and saying
    # so loudly is better than returning a confident 0.
    if address == NATIVE_MINT:
        checks.observe(
            "SUPPLY FIELD IS NOT MAINTAINED FOR THIS MINT",
            "this is the native (wrapped SOL) mint; MintTo and Burn reject "
            "native accounts, so its supply field stays 0 no matter how much "
            "wSOL exists — do not read the supply below as a token count",
        )
        if not quiet:
            print("  !! NATIVE MINT: the supply field below is always 0 and does "
                  "not\n     count wrapped SOL. Supply and ceiling assertions "
                  "against this\n     mint mean nothing.\n", file=out)

    checks.observe("supply (base units)", mint["supplyBaseUnits"])
    checks.observe("decimals", mint["decimals"])
    checks.observe("supply (whole tokens)", supply_human)
    checks.observe("mint authority", mint_authority)
    checks.observe("freeze authority", freeze_authority)

    # --- 3. structural assertions, made on every run ------------------------
    # These hold for any mint and are checked whether or not the caller passed
    # an --expect flag, so that a bare run still means something.
    checks.expect_true(
        "the mint is initialised, so its supply field is meaningful",
        mint["isInitialized"],
        "isInitialized = true at byte offset 45",
    )
    checks.expect_true(
        "the supply fits in the u64 the field is stored in "
        "(a decode that overflows would be a decode of the wrong bytes)",
        0 <= mint["supplyBaseUnits"] < 2 ** 64,
        f"supply = {mint['supplyBaseUnits']}",
    )
    if owner == TOKEN_PROGRAM:
        checks.expect(
            "the account is exactly the 82 bytes of the SPL mint layout, with "
            "no trailing data",
            len(account["data"]), MINT_LEN,
        )

    # --- 4. the caller's assertions ----------------------------------------
    if expect_supply is not None:
        expected_units = parse_whole_tokens(str(expect_supply), mint["decimals"])
        checks.expect(
            "the supply on chain is exactly the claimed amount",
            f"{mint['supplyBaseUnits']} base units ({supply_human} tokens)",
            f"{expected_units} base units ({scale(expected_units, mint['decimals'])} tokens)",
        )
    # A ceiling claim ("there will only ever be N of these") is a different
    # claim from an exact-count claim, and it is the one that does not rot.
    # An --expect-supply assertion against a token that burns is false the
    # moment the next burn lands, which makes a published reproduction command
    # stop reproducing. A ceiling survives every burn.
    #
    # It takes two facts, not one, and they are asserted separately so a
    # failure says which half broke:
    #   (a) the supply today is at or below the ceiling; and
    #   (b) the mint authority is unset, so no future transaction can lift it
    #       above the ceiling.
    # (b) is the half that matters. Without it a "max supply" is a promise,
    # not a cap, and this checker must not let a mintable token past on the
    # strength of (a) alone.
    if expect_max_supply is not None:
        cap_units = parse_whole_tokens(str(expect_max_supply), mint["decimals"])
        checks.expect_true(
            f"the supply on chain is at or below the claimed ceiling of "
            f"{scale(cap_units, mint['decimals'])} tokens",
            mint["supplyBaseUnits"] <= cap_units,
            f"{mint['supplyBaseUnits']} base units ({supply_human}) vs a ceiling "
            f"of {cap_units} base units"
            + ("" if mint["supplyBaseUnits"] <= cap_units else " — OVER THE CEILING"),
        )
        checks.expect_true(
            "the ceiling is enforced by the chain and not by a promise: the "
            "mint authority is unset, so no transaction can ever raise the "
            "supply above it",
            mint_authority is None,
            "mint authority is unset" if mint_authority is None else
            f"NO — {mint_authority} can mint more at will, so this ceiling is "
            "not enforced by anything",
        )

    if expect_decimals is not None:
        checks.expect("decimals is the claimed value", mint["decimals"], expect_decimals)

    for flag, found, label, power in (
        (expect_mint_authority, mint_authority, "mint authority", "create new tokens"),
        (expect_freeze_authority, freeze_authority, "freeze authority", "freeze balances"),
    ):
        if flag is None:
            continue
        if str(flag).lower() in ("none", "null", "revoked", "burned"):
            checks.expect_true(
                f"the {label} is unset, so nobody can {power} — the cap is "
                "enforced by the chain, not by a promise",
                found is None,
                "none" if found is None else f"IT IS SET, to {found}",
            )
        else:
            if not lib.is_valid_pubkey(str(flag)):
                raise lib.CheckerError(
                    f"--expect-{label.replace(' ', '-')} got {flag!r}, which is "
                    "neither 'none' nor a valid address"
                )
            checks.expect(f"the {label} is the claimed account", found, flag)

    facts = {
        "checkedAt": lib.utc_now(),
        "rpc": lib.mask_url(url or lib.rpc_url()),
        "mintAddress": address,
        "owner": owner,
        "programName": program_name,
        "accountBytes": len(account["data"]),
        "rawBaseLayoutHex": account["data"][:MINT_LEN].hex(),
        "tokenProgramLoader": loader,
        "mint": dict(mint, supplyWholeTokens=supply_human),
        "assertions": checks.rows,
    }
    return checks, facts


# ---------------------------------------------------------------------------
# Self-test — the negative control
# ---------------------------------------------------------------------------
# A check that cannot fail proves nothing. This mode runs the checker against
# inputs whose right answer is already known, INCLUDING inputs where the right
# answer is "fail", and confirms it says so. If the negative controls ever
# start passing, this checker is broken and its verdicts are worthless.

# Wrapped SOL. Its mint authority and freeze authority are both unset and its
# decimals are 9; it is about as fixed a landmark as Solana has.
WSOL = "So11111111111111111111111111111111111111112"
WSOL_DECIMALS = 9
# Same account, named for the role it plays in check() rather than in the
# self-test: the SPL Token program special-cases it and never updates its
# supply field. See the warning in check().
NATIVE_MINT = WSOL

# USDC. Circle mints and burns it continuously, so its mint authority and
# freeze authority are both SET. It is the control for "the checker notices
# when an authority exists".
USDC = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDC_DECIMALS = 6

# An account that exists and is not a mint: the SPL Token program itself.
NOT_A_MINT = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"

# BONK. The landmark for ceiling claims: its mint authority is unset, so its
# supply can only fall, and — unlike the native mint — its supply field is a
# real number that the program actually maintains. A ceiling above today's
# supply is therefore true permanently, which is what makes it usable as a
# control that will not rot.
BONK = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"
BONK_CEILING = "100,000,000,000,000"   # 100 trillion; supply is ~88 trillion


def _synthetic_mint(mint_auth_tag=1, supply=123456789, decimals=6,
                    initialized=1, freeze_tag=0) -> bytes:
    """Build 82 bytes of a mint by hand, for the offline decode controls."""
    return (
        mint_auth_tag.to_bytes(4, "little")
        + bytes(range(32))                       # a recognisable authority key
        + supply.to_bytes(8, "little")
        + bytes([decimals, initialized])
        + freeze_tag.to_bytes(4, "little")
        + bytes(32)
    )


def self_test(url=None) -> int:
    """Run every control. Returns the exit code: 0 all correct, 1 a control was
    wrong, 2 the network prevented the online controls from running."""
    print("SELF-TEST — does this checker give the right answer on known inputs?")
    print("=" * 70)
    print(f"RPC:  {lib.mask_url(url or lib.rpc_url())}")
    print(f"Time: {lib.utc_now()}")
    print("")

    results = []

    def record(name, ok, detail, blocked=False):
        results.append({"name": name, "ok": ok, "blocked": blocked, "detail": detail})
        tag = "BLOCKED" if blocked else ("ok" if ok else "WRONG")
        print(f"  [{tag:>7}] {name}")
        print(f"            {detail}")

    # -- Control 1: offline. The decoder reads bytes we built ourselves. -----
    try:
        decoded = _synthetic_mint_decode()
        ok = (decoded["supplyBaseUnits"] == 123456789
              and decoded["decimals"] == 6
              and decoded["freezeAuthority"] is None
              and decoded["mintAuthority"] is not None)
        record("the decoder reads a mint built by hand, byte for byte", ok,
               f"supply={decoded['supplyBaseUnits']}, decimals={decoded['decimals']}, "
               f"freeze={decoded['freezeAuthority']}, mint={decoded['mintAuthority'][:12]}...")
    except lib.CheckerError as exc:
        record("the decoder reads a mint built by hand, byte for byte", False, str(exc))

    # -- Control 2: offline, NEGATIVE. A COption tag of 2 is impossible and
    #    must be refused, not read as "set" or "unset". --------------------
    try:
        decode_mint(_synthetic_mint(mint_auth_tag=2))
        record("KNOWN-BAD: an impossible COption tag is refused", False,
               "the decoder accepted a tag of 2 — it should have raised")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: an impossible COption tag is refused", True,
               f"refused with: {str(exc)[:80]}")

    # -- Control 3: offline, NEGATIVE. Reading the 4-byte COption as 1 byte
    #    is the classic way to get this layout wrong. Confirm the decoder is
    #    not doing that, by checking it lands on the right supply when the
    #    wrong reading would land on a different number. --------------------
    try:
        shifted = decode_mint(_synthetic_mint(supply=1))
        record("the 4-byte COption tag is read as 4 bytes, not 1",
               shifted["supplyBaseUnits"] == 1,
               f"supply decoded as {shifted['supplyBaseUnits']} (wanted 1; a "
               "1-byte tag misread would give a huge number here)")
    except lib.CheckerError as exc:
        record("the 4-byte COption tag is read as 4 bytes, not 1", False, str(exc))

    # -- Control 4: offline, NEGATIVE. Too-short data must raise. -----------
    try:
        decode_mint(b"\x00" * 40)
        record("KNOWN-BAD: a too-short account is refused", False,
               "the decoder accepted 40 bytes as a mint")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a too-short account is refused", True,
               f"refused with: {str(exc)[:80]}")

    # -- Control 5: offline. Exact decimal arithmetic, no floats. -----------
    try:
        units = parse_whole_tokens("10,000,000,000", 6)
        back = scale(units, 6)
        near_miss = scale(units - 1, 6)
        ok = (units == 10_000_000_000 * 10 ** 6
              and back == "10,000,000,000.000000"
              and near_miss == "9,999,999,999.999999")
        record("supply arithmetic is exact — one base unit short does not "
               "round up to the claimed number", ok,
               f"{units} -> {back}; one less -> {near_miss}")
    except lib.CheckerError as exc:
        record("supply arithmetic is exact", False, str(exc))

    # -- Control 6: offline, NEGATIVE. An over-precise claim must be refused
    #    rather than truncated into a match. ------------------------------
    try:
        parse_whole_tokens("1.0000001", 6)
        record("KNOWN-BAD: a claim with more decimals than the mint is refused",
               False, "1.0000001 was accepted for a 6-decimal mint")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a claim with more decimals than the mint is refused",
               True, f"refused with: {str(exc)[:80]}")

    # -- Control 7: online, POSITIVE. Known-good input must pass. -----------
    try:
        checks, _ = check(WSOL, expect_decimals=WSOL_DECIMALS,
                          expect_mint_authority="none",
                          expect_freeze_authority="none", url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-GOOD: wrapped SOL has 9 decimals and no authorities",
               code == 0, f"exit code {code} (wanted 0)")
    except lib.CheckerError as exc:
        record("KNOWN-GOOD: wrapped SOL has 9 decimals and no authorities",
               False, str(exc), blocked=True)

    # -- Control 8: online, NEGATIVE. Wrong decimals MUST fail. -------------
    try:
        checks, _ = check(USDC, expect_decimals=USDC_DECIMALS + 3, url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: a false decimals claim produces exit 1",
               code == 1, f"exit code {code} (wanted 1 — a wrong claim must fail)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a false decimals claim produces exit 1", False,
               str(exc), blocked=True)

    # -- Control 9: online, NEGATIVE. This is the control that matters most
    #    for this checker: USDC's mint authority IS set, so claiming it is
    #    unset must fail. If this ever passes, every "supply is capped"
    #    verdict this script has printed is worthless. ---------------------
    try:
        checks, _ = check(USDC, expect_mint_authority="none", url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: claiming USDC's mint authority is revoked produces exit 1",
               code == 1, f"exit code {code} (wanted 1 — USDC is mintable by Circle)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: claiming USDC's mint authority is revoked produces exit 1",
               False, str(exc), blocked=True)

    # -- Control 10: online, NEGATIVE. A false supply claim MUST fail. ------
    try:
        checks, _ = check(WSOL, expect_supply="1", url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: a false supply claim produces exit 1",
               code == 1, f"exit code {code} (wanted 1)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a false supply claim produces exit 1", False,
               str(exc), blocked=True)

    # -- Control 11: online. The loader decode must find the SPL Token program
    #    immutable. If Solana ever re-adds an upgrade authority to it, this
    #    control failing is itself the news. --------------------------------
    try:
        loader = program_upgrade_authority(TOKEN_PROGRAM, url=url)
        record("the SPL Token program decodes as immutable (no upgrade authority)",
               loader["upgradeAuthority"] is None,
               f"upgrade authority = {loader['upgradeAuthority']}, "
               f"programdata = {loader['programDataAddress']}")
    except lib.CheckerError as exc:
        record("the SPL Token program decodes as immutable (no upgrade authority)",
               False, str(exc), blocked=True)

    # -- Control 12: online, NEGATIVE. The loader decode must refuse an
    #    account that is not a program at all. ------------------------------
    try:
        program_upgrade_authority(WSOL, url=url)
        record("KNOWN-BAD: the loader decode refuses a non-program account", False,
               "it read an upgrade authority out of a mint account")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: the loader decode refuses a non-program account", True,
               f"refused with: {str(exc)[:80]}")

    # -- Control 13: online, NEGATIVE. A non-mint account must be refused,
    #    not decoded into a confident wrong supply. -------------------------
    try:
        check(NOT_A_MINT, url=url, quiet=True)
        record("KNOWN-BAD: a non-mint account is refused", False,
               "the checker decoded a non-mint account instead of refusing")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a non-mint account is refused", True,
               f"refused with: {str(exc)[:80]}")

    # -- Control 14: online, POSITIVE. A ceiling that is genuinely above the
    #    supply, on a mint whose authority is unset, must pass. BONK and not
    #    wrapped SOL, because wSOL's supply field is a permanent 0 and any
    #    ceiling would clear it vacuously. ----------------------------------
    try:
        checks, facts = check(BONK, expect_max_supply=BONK_CEILING,
                              url=url, quiet=True)
        code = checks.exit_code()
        supply = facts["mint"]["supplyBaseUnits"]
        record("KNOWN-GOOD: a true supply ceiling on a fixed-supply mint passes",
               code == 0 and supply > 0,
               f"exit code {code} (wanted 0), supply {supply} (wanted > 0, so "
               "the comparison is not vacuous)")
    except lib.CheckerError as exc:
        record("KNOWN-GOOD: a true supply ceiling on a fixed-supply mint passes",
               False, str(exc), blocked=True)

    # -- Control 15: online, NEGATIVE. A ceiling below the actual supply must
    #    fail. Confirms the comparison is not simply always true.
    #
    #    This deliberately checks the arithmetic ROW rather than the exit
    #    code. USDC fails the mint-authority half of a ceiling claim as well,
    #    so an exit code of 1 here would not prove the comparison ran at all.
    #
    #    It does not use wrapped SOL. The first draft of this control did, and
    #    it failed: the native mint's supply field reads 0 forever, because
    #    MintTo and Burn both reject native accounts outright
    #    (TokenError::NativeNotSupported, processor.rs lines 537 and 604), so
    #    the field is never written. A ceiling of 1 token was therefore true
    #    for wSOL and the control passed when it should have failed. Leaving
    #    that note here because it is exactly the trap warn_native_mint()
    #    below now warns about. -------------------------------------------
    try:
        checks, _ = check(USDC, expect_max_supply="1", url=url, quiet=True)
        row = next((r for r in checks.rows
                    if "at or below the claimed ceiling" in r["label"]), None)
        if row is None:
            record("KNOWN-BAD: a ceiling below the real supply produces exit 1",
                   False, "the ceiling assertion did not run at all")
        else:
            record("KNOWN-BAD: a ceiling below the real supply produces exit 1",
                   row["kind"] == "fail" and checks.exit_code() == 1,
                   f"ceiling assertion recorded '{row['kind']}' (wanted 'fail'), "
                   f"exit code {checks.exit_code()} (wanted 1)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a ceiling below the real supply produces exit 1",
               False, str(exc), blocked=True)

    # -- Control 16: online, NEGATIVE. THE control for --expect-max-supply.
    #    USDC's supply is far below a trillion, so the arithmetic half of the
    #    ceiling claim is true — but Circle holds the mint authority, so the
    #    ceiling is not enforced by anything and the claim must still fail.
    #    If this control ever passes, this checker is calling a promise a cap
    #    and every ceiling verdict it has printed is worthless. -------------
    try:
        checks, _ = check(USDC, expect_max_supply="1,000,000,000,000",
                          url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: a ceiling on a MINTABLE token fails even though the "
               "supply is under it", code == 1,
               f"exit code {code} (wanted 1 — Circle can mint past any ceiling)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a ceiling on a MINTABLE token fails even though the "
               "supply is under it", False, str(exc), blocked=True)

    # -- Control 17: online. The native-mint trap must be announced, not
    #    silently passed over. wSOL's supply field reads 0; a reader who is
    #    not told that will read it as "no wrapped SOL exists". -------------
    try:
        checks, facts = check(WSOL, url=url, quiet=True)
        warned = any("SUPPLY FIELD IS NOT MAINTAINED" in r["label"]
                     for r in checks.rows)
        supply = facts["mint"]["supplyBaseUnits"]
        record("the native mint's unmaintained supply field is flagged, not "
               "reported as a count", warned and supply == 0,
               f"warning present: {warned}; supply field reads {supply} "
               "(0 is expected and is exactly why the warning is needed)")
    except lib.CheckerError as exc:
        record("the native mint's unmaintained supply field is flagged, not "
               "reported as a count", False, str(exc), blocked=True)

    # -- Verdict ------------------------------------------------------------
    wrong = [r for r in results if not r["ok"] and not r["blocked"]]
    blocked = [r for r in results if r["blocked"]]
    print("")
    print("-" * 70)
    if wrong:
        print(f"SELF-TEST FAILED: {len(wrong)} control(s) gave the wrong answer.")
        print("Do not trust this checker's verdicts until this is fixed.")
        return 1
    if blocked:
        print(f"SELF-TEST INCOMPLETE: {len(blocked)} control(s) could not reach the")
        print("chain. The offline controls passed. This is NOT a clean bill of health.")
        return 2
    negative = sum(1 for r in results if "KNOWN-BAD" in r["name"])
    print(f"SELF-TEST PASSED: {len(results)} controls, including {negative} negative")
    print("controls that had to fail and did.")
    return 0


def _synthetic_mint_decode() -> dict:
    """Decode the hand-built mint. Separate so control 1 reads cleanly."""
    return decode_mint(_synthetic_mint())


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the supply, decimals, mint authority and freeze "
                    "authority of an SPL token mint on Solana.",
        epilog="Exit 0 = all assertions held, 1 = an assertion is false, "
               "2 = could not check.",
    )
    parser.add_argument("address", nargs="?", help="the mint address (base58)")
    parser.add_argument("--expect-supply", metavar="N",
                        help="assert the supply is exactly N whole tokens "
                             "(commas allowed, e.g. 10,000,000,000)")
    parser.add_argument("--expect-max-supply", metavar="N",
                        help="assert the supply is at most N whole tokens AND "
                             "that the mint authority is unset, so it can never "
                             "exceed N. Use this for 'there will only ever be N' "
                             "claims: unlike --expect-supply it survives burns.")
    parser.add_argument("--expect-decimals", type=int, metavar="N",
                        help="assert the mint has N decimals")
    parser.add_argument("--expect-mint-authority", metavar="NONE|ADDRESS",
                        help="assert the mint authority is unset ('none') or is "
                             "exactly this address")
    parser.add_argument("--expect-freeze-authority", metavar="NONE|ADDRESS",
                        help="assert the freeze authority is unset ('none') or "
                             "is exactly this address")
    parser.add_argument("--rpc", metavar="URL",
                        help="Solana RPC endpoint (default: $SOLANA_RPC_URL, "
                             "else the public mainnet endpoint)")
    parser.add_argument("--json", metavar="PATH",
                        help="also write the decoded facts here as JSON")
    parser.add_argument("--self-test", action="store_true",
                        help="run against known-good and known-bad inputs and "
                             "confirm the answers are right")
    args = parser.parse_args()

    if args.self_test:
        return self_test(url=args.rpc)

    if not args.address:
        parser.print_help()
        print("\nNo address given. Try --self-test to confirm this checker works.")
        return 2

    try:
        checks, facts = check(
            args.address,
            expect_supply=args.expect_supply,
            expect_max_supply=args.expect_max_supply,
            expect_decimals=args.expect_decimals,
            expect_mint_authority=args.expect_mint_authority,
            expect_freeze_authority=args.expect_freeze_authority,
            url=args.rpc,
        )
    except lib.CheckerError as exc:
        # Could not check. Deliberately NOT exit 1: "I could not find out" and
        # "I found out, and the claim is false" are different answers and this
        # project never blurs them.
        print(f"\nCOULD NOT CHECK: {exc}")
        return 2

    checks.print_report()

    if args.json:
        Path(args.json).write_text(
            json.dumps(facts, indent=2, sort_keys=True), encoding="utf-8")
        print(f"\nwrote {args.json}")

    code = checks.exit_code()
    print("")
    if code == 0:
        print("RESULT: every assertion held.")
    elif code == 1:
        print("RESULT: at least one assertion is FALSE. See the FAIL lines above.")
    else:
        print("RESULT: incomplete — something could not be checked.")
    return code


if __name__ == "__main__":
    sys.exit(main())
