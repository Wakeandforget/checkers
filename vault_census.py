#!/usr/bin/env python3
"""
vault_census.py — is the fund a protocol says it holds actually in its vaults?

CLAIM CLASS: "our insurance fund / treasury / reserve is intact", where the
fund lives in a family of vaults at program-derived addresses. Almost every
Solana protocol holds pooled money this way: one token account per market,
per asset, or per index, each at a PDA derived from a fixed seed string plus
a little-endian index. The project publishes a sentence; the vaults publish
the truth.

This script derives EVERY vault in the family from the program's own declared
seeds, reads each one as a raw SPL token account, and reports the balance. If
a vault is empty it walks that vault's own signature history backwards until
it finds the transaction that took the money out, and names the destination
and the signer.

RUN:
    python3 checkers/vault_census.py --preset drift-insurance-fund
    python3 checkers/vault_census.py --program dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH \\
        --seed insurance_fund_vault --index-range 0:64 --authority-seed drift_signer

THE DEPOSITOR SIDE (--shares, added wake 14)
--------------------------------------------
A vault census answers "is the money there". It does NOT answer "does anyone
still have a recorded claim on it", and those are different questions with
different answers. A fund can be empty with the books wiped (depositors were
paid out, or written off) or empty with the books still crediting depositors
in full (their recorded asset now redeems for nothing). Only the second is a
dangling claim, and a census of token balances cannot tell them apart.

`--shares` reads the ledger side: for each market it decodes the protocol's
own share accounting, cross-checks it against the vault the same market names,
and computes what those shares actually redeem for using the protocol's own
formula. `--stakers` additionally censuses every individual depositor account.

    python3 checkers/vault_census.py --preset drift-insurance-fund --shares
    python3 checkers/vault_census.py --preset drift-insurance-fund --shares --stakers

Why a new checker rather than an extension
------------------------------------------
`fee_split.py --holds/--at` answers "address A holds mint M", and it was the
closest fit. It takes an OWNER and enumerates that owner's token accounts.
That is the wrong shape here for a reason that matters: the owner of Drift's
insurance-fund vaults is also the owner of its collateral vaults, its revenue
pools and its fee accounts, so "what the owner holds" cannot distinguish the
insurance fund from anything else. The identifying fact about an insurance
fund vault is its DERIVATION — seed string plus market index — not its owner.
So the census is built around find_program_address, and the owner becomes a
control rather than the lookup key.

Exit codes
----------
  0  every assertion held
  1  at least one assertion is false
  2  it could not be checked (network, rate limit, unusable input)
"""

import argparse
import base64
import datetime
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import _lib as lib  # noqa: E402

TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
SYSTEM_PROGRAM = "11111111111111111111111111111111"

# ---------------------------------------------------------------------------
# Presets. Each one pins the program id and the seeds to the project's OWN
# published on-chain source, at a commit hash, so a reader can check that the
# seed string in this file is the seed string the program enforces.
# ---------------------------------------------------------------------------

PRESETS = {
    "drift-insurance-fund": {
        "program": "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH",
        "seed": b"insurance_fund_vault",
        "index_range": (0, 64),
        "authority_seed": b"drift_signer",
        "source": (
            "drift-labs/protocol-v2 (repo now redirects to "
            "velocity-exchange/protocol-v2), commit "
            "13e8e9b8d614f3b62e3a65a8c372c819e6529aeb, "
            "programs/drift/src/instructions/if_staker.rs line 994: "
            'seeds = [b"insurance_fund_vault".as_ref(), '
            "market_index.to_le_bytes().as_ref()] ; program id from "
            "programs/drift/src/lib.rs line 65, declare_id!"
        ),
        # --shares: the ledger side of the same fund.
        "shares": {
            "market_seed": b"spot_market",
            "market_account": "SpotMarket",
            "stake_account": "InsuranceFundStake",
            "source": (
                "drift-labs/protocol-v2 (repo now redirects to "
                "velocity-exchange/protocol-v2), commit "
                "13e8e9b8d614f3b62e3a65a8c372c819e6529aeb: "
                'spot_market PDA seeds = [b"spot_market", '
                "state.number_of_spot_markets.to_le_bytes()] "
                "(instructions/admin.rs line 5272); struct SpotMarket and "
                "struct InsuranceFund in state/spot_market.rs; struct "
                "InsuranceFundStake in state/insurance_fund_stake.rs; "
                "redemption formula if_shares_to_vault_amount() in "
                "math/insurance.rs line 44"
            ),
        },
    },
}

# ---------------------------------------------------------------------------
# Byte offsets for Drift's SpotMarket / InsuranceFundStake accounts.
#
# These are DERIVED, not guessed, and the derivation is checkable by hand.
# Anchor's zero_copy is #[repr(C)]; on Solana's SBF target u128 has alignment
# 8, not 16, so the declared field order lays out with no interior padding at
# all. Summing the declared fields of SpotMarket in order gives exactly 768
# bytes, and the program's own `impl Size for SpotMarket { const SIZE = 776 }`
# is 768 + the 8-byte Anchor discriminator. That the two numbers meet is the
# arithmetic check that this table is right; the `market_index` assertion in
# share_census() is the live check.
#
# Offsets below are into the FULL account data, i.e. discriminator included.
# ---------------------------------------------------------------------------

SPOT_MARKET_LEN = 776
SM = {
    "pubkey": (8, 40),            # Pubkey  — the market's own address
    "mint": (72, 104),            # Pubkey  — token mint of the market
    "name": (136, 168),           # [u8;32] — e.g. "USDC"
    # struct InsuranceFund begins at 304 and is 112 bytes.
    "if_vault": (304, 336),       # Pubkey  — the insurance fund vault
    "if_total_shares": (336, 352),  # u128
    "if_user_shares": (352, 368),   # u128
    "if_shares_base": (368, 384),   # u128  — rebase exponent
    "decimals": (680, 684),       # u32
    "market_index": (684, 686),   # u16
}

IF_STAKE_LEN = 136
IFS = {
    "authority": (8, 40),                       # Pubkey
    "if_shares": (40, 56),                      # u128 (private field)
    "last_withdraw_request_shares": (56, 72),   # u128
    "if_base": (72, 88),                        # u128
    "last_valid_ts": (88, 96),                  # i64 — unix ts, touched on
                                                #       every stake operation
    "last_withdraw_request_value": (96, 104),   # u64
    "market_index": (120, 122),                 # u16
}


def _u(data: bytes, span) -> int:
    lo, hi = span
    return int.from_bytes(data[lo:hi], "little")


def _key(data: bytes, span) -> str:
    lo, hi = span
    return lib.b58encode(data[lo:hi])


def if_shares_to_vault_amount(n_shares: int, total_shares: int,
                              vault_balance: int) -> int:
    """What a holding of `n_shares` redeems for, right now.

    This is a transcription of Drift's own math/insurance.rs line 44. It is
    reproduced rather than approximated because the whole question of this
    check is what the protocol itself would pay out, not what seems fair:

        if total_if_shares > 0 { vault_balance * n_shares / total_if_shares }
        else { 0 }

    Note the shape of it. The vault balance is a FACTOR in the numerator, so
    a zero vault makes every holding, of any size, redeem for exactly zero.
    Shares are a claim on a pot, not a stored amount.
    """
    if n_shares > total_shares:
        raise lib.CheckerError(
            f"n_shares ({n_shares}) > total_shares ({total_shares}); the "
            "program's own validate! rejects this, so the decode is wrong")
    if total_shares <= 0:
        return 0
    return (vault_balance * n_shares) // total_shares


def decode_spot_market(address: str, account: dict, expect_disc: bytes) -> dict:
    """Read an account as a Drift SpotMarket, or refuse.

    Same rule as parse_token_account: a checker that returns a clean zero for
    an account it could not parse has turned "I could not read the books"
    into "the books say nobody is owed anything", which are opposite
    findings. Every failure raises.
    """
    if account is None:
        raise lib.CheckerError(f"{address} does not exist on chain")
    data = account.get("data")
    if not (isinstance(data, list) and len(data) == 2 and data[1] == "base64"):
        raise lib.CheckerError(f"{address} did not come back as base64 data")
    raw = base64.b64decode(data[0])
    if len(raw) != SPOT_MARKET_LEN:
        raise lib.CheckerError(
            f"{address} is {len(raw)} bytes, not the {SPOT_MARKET_LEN} bytes "
            "SpotMarket::SIZE declares; refusing to read fields out of it")
    if raw[:8] != expect_disc:
        raise lib.CheckerError(
            f"{address} has discriminator {raw[:8].hex()}, not SpotMarket's "
            f"{expect_disc.hex()}; this is a different account type")
    total = _u(raw, SM["if_total_shares"])
    user = _u(raw, SM["if_user_shares"])
    if user > total:
        raise lib.CheckerError(
            f"{address}: user_shares ({user}) > total_shares ({total}), which "
            "the program forbids; the layout must be wrong")
    name = raw[SM["name"][0]:SM["name"][1]].decode("utf-8", "replace").strip()
    return {
        "address": address,
        "declaredPubkey": _key(raw, SM["pubkey"]),
        "marketIndex": _u(raw, SM["market_index"]),
        "name": name,
        "mint": _key(raw, SM["mint"]),
        "decimals": _u(raw, SM["decimals"]),
        "ifVault": _key(raw, SM["if_vault"]),
        "totalShares": total,
        "userShares": user,
        "sharesBase": _u(raw, SM["if_shares_base"]),
    }


def decode_if_stake(address: str, raw: bytes, expect_disc: bytes) -> dict:
    """Read one depositor's InsuranceFundStake account, or refuse."""
    if len(raw) != IF_STAKE_LEN:
        raise lib.CheckerError(
            f"{address} is {len(raw)} bytes, not the {IF_STAKE_LEN} bytes "
            "InsuranceFundStake::SIZE declares")
    if raw[:8] != expect_disc:
        raise lib.CheckerError(
            f"{address} has discriminator {raw[:8].hex()}, not "
            f"InsuranceFundStake's {expect_disc.hex()}")
    return {
        "address": address,
        "authority": _key(raw, IFS["authority"]),
        "marketIndex": _u(raw, IFS["market_index"]),
        "ifShares": _u(raw, IFS["if_shares"]),
        "ifBase": _u(raw, IFS["if_base"]),
        "lastValidTs": _u(raw, IFS["last_valid_ts"]),
        "withdrawRequestShares": _u(raw, IFS["last_withdraw_request_shares"]),
        "withdrawRequestValue": _u(raw, IFS["last_withdraw_request_value"]),
    }


def index_seed(i: int) -> bytes:
    """A market index as the program writes it: u16, little-endian.

    This is `market_index.to_le_bytes()` in the Anchor account constraint. Two
    bytes, not four and not eight — get this wrong and every address in the
    census is wrong, which is why derive_vault() is pinned by a control below.
    """
    if not 0 <= i <= 0xFFFF:
        raise lib.CheckerError(f"market index {i} does not fit in a u16")
    return i.to_bytes(2, "little")


def derive_vault(program: str, seed: bytes, i: int):
    raw, bump = lib.find_program_address([seed, index_seed(i)],
                                         lib.parse_pubkey(program))
    return lib.b58encode(raw), bump


def derive_authority(program: str, seed: bytes):
    raw, bump = lib.find_program_address([seed], lib.parse_pubkey(program))
    return lib.b58encode(raw), bump


def parse_token_account(address: str, account: dict) -> dict:
    """Read an account as an SPL token account, or refuse.

    A checker that quietly reports 0 for an account it could not parse is
    worse than useless: "the vault is empty" and "I could not read the vault"
    are opposite findings and must never share an output. So every failure
    here raises.
    """
    owner_program = account.get("owner")
    if owner_program not in (TOKEN_PROGRAM, TOKEN_2022_PROGRAM):
        raise lib.CheckerError(
            f"{address} is owned by {owner_program}, which is not an SPL Token "
            "program. This is not a token account and no balance can be read "
            "from it."
        )
    data = account.get("data")
    if not (isinstance(data, dict) and data.get("parsed")):
        raise lib.CheckerError(
            f"{address} did not come back as parsed token data; refusing to "
            "guess at a balance"
        )
    parsed = data["parsed"]
    if parsed.get("type") != "account":
        raise lib.CheckerError(
            f"{address} parses as '{parsed.get('type')}', not a token account"
        )
    info = parsed["info"]
    amount = info["tokenAmount"]
    return {
        "address": address,
        "tokenProgram": owner_program,
        "mint": info["mint"],
        "authority": info["owner"],
        "state": info.get("state"),
        "amountRaw": int(amount["amount"]),
        "decimals": amount["decimals"],
        "amountUi": amount["uiAmountString"],
    }


def utc(ts):
    if not ts:
        return None
    return datetime.datetime.fromtimestamp(ts, datetime.UTC).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def find_last_outflow(address: str, max_tx: int = 10, url: str = None,
                      pause: float = 0.35) -> dict:
    """Walk a token account's own history until the balance goes DOWN.

    Returns the transaction that reduced it, with the destination and the
    signers. Deliberately bounded: if no outflow is found in `max_tx`
    transactions this says so rather than reporting "no outflow", because
    "I did not look far enough" is not the same finding as "nothing left".
    """
    sigs = lib.rpc("getSignaturesForAddress", [address, {"limit": max_tx}],
                   url=url)
    examined = 0
    outflows = []
    for entry in sigs:
        if entry.get("err"):
            continue          # a failed transaction moved nothing
        examined += 1
        if examined > max_tx:
            break
        time.sleep(pause)
        tx = lib.rpc("getTransaction",
                     [entry["signature"],
                      {"encoding": "jsonParsed",
                       "maxSupportedTransactionVersion": 0}], url=url)
        if tx is None:
            continue
        keys = [k["pubkey"] for k in tx["transaction"]["message"]["accountKeys"]]
        signers = [k["pubkey"] for k in tx["transaction"]["message"]["accountKeys"]
                   if k.get("signer")]
        pre = {b["accountIndex"]: b for b in tx["meta"].get("preTokenBalances", [])}
        post = {b["accountIndex"]: b for b in tx["meta"].get("postTokenBalances", [])}
        for idx, key in enumerate(keys):
            if key != address:
                continue
            before = int(pre.get(idx, {}).get("uiTokenAmount", {}).get("amount", "0") or 0)
            after = int(post.get(idx, {}).get("uiTokenAmount", {}).get("amount", "0") or 0)
            if after < before:
                # collect every outflow in the window, not just the newest:
                # the newest is often a dust sweep and the one that matters
                # is the big one behind it.
                gained = []
                for i2, k2 in enumerate(keys):
                    if k2 == address:
                        continue
                    b2 = int(pre.get(i2, {}).get("uiTokenAmount", {}).get("amount", "0") or 0)
                    a2 = int(post.get(i2, {}).get("uiTokenAmount", {}).get("amount", "0") or 0)
                    if a2 > b2:
                        gained.append({
                            "account": k2,
                            "owner": (post.get(i2) or {}).get("owner"),
                            "mint": (post.get(i2) or {}).get("mint"),
                            "delta": a2 - b2,
                        })
                outflows.append({
                    "found": True,
                    "signature": entry["signature"],
                    "when": utc(tx.get("blockTime")),
                    "slot": tx.get("slot"),
                    "signers": signers,
                    "programs": sorted({i.get("programId") for i in
                                        tx["transaction"]["message"]["instructions"]
                                        if i.get("programId")}),
                    "amountRawBefore": before,
                    "amountRawAfter": after,
                    "amountRawOut": before - after,
                    "creditedTo": gained,
                })
    if outflows:
        return {"found": True, "examinedTransactions": examined,
                "outflows": outflows}
    return {"found": False, "examinedTransactions": examined,
            "note": f"no balance decrease in the {examined} most recent "
                    f"successful transactions touching this account"}


# ---------------------------------------------------------------------------
# Controls
# ---------------------------------------------------------------------------

# A vault this script must be able to reproduce offline. Pure arithmetic:
# sha256 over the seeds and the program id. It cannot rot with the chain.
CONTROL_PROGRAM = "dRiftyHA39MWEi3m9aunc5MzRF1JYuBsbn6VPcn33UH"
CONTROL_SEED = b"insurance_fund_vault"
CONTROL_INDEX = 0
CONTROL_VAULT = "2CqkQvYxp9Mq4PqLvAQ1eryYxebUh4Liyn5YMDtXsYci"
CONTROL_BUMP = 253
CONTROL_AUTH_SEED = b"drift_signer"
CONTROL_AUTH = "JCNCMFXo5M5qwUPg2Utu1u6YWp3MbygxqBsBeXXJfrw"
CONTROL_AUTH_BUMP = 254


def self_test(url=None) -> int:
    checks = lib.Checks()

    # -- 1. offline: the derivation reproduces a known vault address.
    got, bump = derive_vault(CONTROL_PROGRAM, CONTROL_SEED, CONTROL_INDEX)
    checks.expect_true(
        "vault PDA derivation reproduces a known address",
        got == CONTROL_VAULT and bump == CONTROL_BUMP,
        f"derived {got} (bump {bump}), expected {CONTROL_VAULT} "
        f"(bump {CONTROL_BUMP})")

    # -- 2. offline NEGATIVE: a wrong seed string must NOT reproduce it.
    wrong, _ = derive_vault(CONTROL_PROGRAM, b"insurance_fund_vaults",
                            CONTROL_INDEX)
    checks.expect_true(
        "a wrong seed string derives a DIFFERENT address (the derivation is "
        "actually sensitive to the seed)",
        wrong != CONTROL_VAULT,
        f"wrong-seed derivation gave {wrong}")

    # -- 3. offline NEGATIVE: the index width matters. u32 instead of u16
    #       must give a different address, or the census is indexing nothing.
    raw32, _ = lib.find_program_address(
        [CONTROL_SEED, CONTROL_INDEX.to_bytes(4, "little")],
        lib.parse_pubkey(CONTROL_PROGRAM))
    checks.expect_true(
        "a u32 index derives a DIFFERENT address than a u16 index",
        lib.b58encode(raw32) != CONTROL_VAULT,
        f"u32 derivation gave {lib.b58encode(raw32)}")

    # -- 4. offline: the authority PDA reproduces.
    auth, abump = derive_authority(CONTROL_PROGRAM, CONTROL_AUTH_SEED)
    checks.expect_true(
        "authority PDA derivation reproduces a known address",
        auth == CONTROL_AUTH and abump == CONTROL_AUTH_BUMP,
        f"derived {auth} (bump {abump}), expected {CONTROL_AUTH} "
        f"(bump {CONTROL_AUTH_BUMP})")

    # -- 5. offline: every derived vault must be OFF the ed25519 curve.
    #       An on-curve "vault" would be somebody's private key.
    on_curve = [i for i in range(0, 16)
                if lib.is_on_curve(lib.b58decode(
                    derive_vault(CONTROL_PROGRAM, CONTROL_SEED, i)[0]))]
    checks.expect_true(
        "every derived vault address is off the ed25519 curve (no private "
        "key can exist for it)",
        not on_curve,
        f"on-curve derivations at indices {on_curve}" if on_curve
        else "indices 0-15 all off-curve")

    # -- 6. offline NEGATIVE: parse_token_account must REFUSE a non-token
    #       account rather than reporting a clean-looking zero.
    try:
        parse_token_account("fake", {"owner": SYSTEM_PROGRAM, "data": ["", "base64"]})
        refused = False
    except lib.CheckerError:
        refused = True
    checks.expect_true(
        "a System-owned account is REFUSED as a token account rather than "
        "read as a zero balance",
        refused,
        "parse_token_account raised" if refused
        else "parse_token_account returned a balance for a non-token account")

    # -- 7. offline NEGATIVE: an out-of-range index must raise, not wrap.
    try:
        index_seed(70000)
        raised = False
    except lib.CheckerError:
        raised = True
    checks.expect_true("an index too large for a u16 raises", raised,
                       "index_seed(70000) raised" if raised else "it did not")

    # -- 8. online: the live control vault must really be a token account
    #       whose authority is the separately-derived authority PDA. Three
    #       independent things have to agree: the seed string taken from the
    #       program source, PDA arithmetic done here, and a field in an
    #       account on the chain. A misread layout cannot fake that.
    try:
        acc = lib.rpc("getAccountInfo",
                      [CONTROL_VAULT, {"encoding": "jsonParsed"}], url=url)["value"]
        if acc is None:
            checks.blocked("live control vault exists",
                           f"{CONTROL_VAULT} does not exist")
        else:
            info = parse_token_account(CONTROL_VAULT, acc)
            checks.expect_true(
                "the live vault's authority field equals the independently "
                "derived authority PDA",
                info["authority"] == CONTROL_AUTH,
                f"authority on chain is {info['authority']}, derived "
                f"{CONTROL_AUTH}")
    except lib.CheckerError as exc:
        checks.blocked("live control vault check", str(exc))

    # -----------------------------------------------------------------
    # Controls for the --shares path (wake 14).
    # -----------------------------------------------------------------
    sm_disc = lib.anchor_discriminator("SpotMarket")
    ifs_disc = lib.anchor_discriminator("InsuranceFundStake")

    # -- 9. offline: the redemption formula's defining property. An empty
    #       vault pays zero on ANY holding, however large. If this is wrong
    #       the whole finding is wrong, so it is asserted, not assumed.
    checks.expect(
        "a share balance against an EMPTY vault redeems for exactly zero",
        if_shares_to_vault_amount(2_352_803_551_671, 3_841_390_135_873, 0), 0)

    # -- 10. offline: and it is not simply always zero — pro rata on a funded
    #        vault. A formula that returns 0 unconditionally would "prove" the
    #        finding without reading anything.
    checks.expect(
        "the same formula returns a correct pro-rata amount when the vault "
        "is funded (half the shares of a 1000-token vault -> 500)",
        if_shares_to_vault_amount(50, 100, 1000), 500)

    # -- 11. offline NEGATIVE: shares exceeding the total must raise, matching
    #        the program's own validate!.
    try:
        if_shares_to_vault_amount(101, 100, 1000)
        raised = False
    except lib.CheckerError:
        raised = True
    checks.expect_true("n_shares > total_shares raises rather than returning "
                       "a number", raised,
                       "it raised" if raised else "it returned a value")

    # -- 12. offline NEGATIVE: the SpotMarket decoder must REFUSE an account
    #        of the wrong length and an account with the wrong discriminator,
    #        rather than reading zeros out of it.
    for label, blob in (
            ("wrong length", b"\x00" * 100),
            ("wrong discriminator", b"\x01" * 8 + b"\x00" * (SPOT_MARKET_LEN - 8))):
        try:
            decode_spot_market("fake", {"data": [base64.b64encode(blob).decode(),
                                                 "base64"]}, sm_disc)
            refused = False
        except lib.CheckerError:
            refused = True
        checks.expect_true(
            f"a SpotMarket account with the {label} is REFUSED, not decoded "
            "as a market with zero shares", refused,
            "decoder raised" if refused else "decoder returned a result")

    # -- 13. offline NEGATIVE: the offsets must be load-bearing. Decoding
    #        total_shares eight bytes off must give a DIFFERENT number. If it
    #        did not, the field could be anywhere and the decode would prove
    #        nothing about the layout.
    probe = bytearray(SPOT_MARKET_LEN)
    probe[:8] = sm_disc
    probe[SM["if_total_shares"][0]:SM["if_total_shares"][1]] = \
        (12345).to_bytes(16, "little")
    shifted = int.from_bytes(probe[SM["if_total_shares"][0] + 8:
                                   SM["if_total_shares"][1] + 8], "little")
    checks.expect_true(
        "the total_shares offset is load-bearing: reading 8 bytes away gives "
        "a different value",
        shifted != 12345, f"shifted read gave {shifted}, true value 12345")

    # -- 14. online NEGATIVE: a wrong account discriminator must match ZERO
    #        accounts. This proves the getProgramAccounts filter that finds
    #        48k depositor accounts is actually filtering, and not just
    #        returning whatever the endpoint felt like.
    try:
        bogus = bytes([ifs_disc[0] ^ 0xFF]) + ifs_disc[1:]
        got = lib.rpc("getProgramAccounts", [CONTROL_PROGRAM, {
            "encoding": "base64",
            "filters": [{"dataSize": IF_STAKE_LEN},
                        {"memcmp": {"offset": 0,
                                    "bytes": lib.b58encode(bogus)}}],
            "dataSlice": {"offset": 0, "length": 0},
        }], url=url, timeout=120)
        checks.expect("a WRONG InsuranceFundStake discriminator matches no "
                      "accounts", len(got), 0)
    except lib.CheckerError as exc:
        checks.blocked("wrong-discriminator control", str(exc))

    # -- 15. online: the two derivations meet on the control market. The
    #        insurance_fund.vault field inside SpotMarket[0] must equal the
    #        insurance_fund_vault PDA derived from a completely different seed
    #        string. Nothing about a misread layout produces that by chance.
    try:
        sm_addr, _ = lib.find_program_address(
            [b"spot_market", index_seed(CONTROL_INDEX)],
            lib.parse_pubkey(CONTROL_PROGRAM))
        acc = lib.rpc("getAccountInfo",
                      [lib.b58encode(sm_addr), {"encoding": "base64"}],
                      url=url)["value"]
        m = decode_spot_market(lib.b58encode(sm_addr), acc, sm_disc)
        checks.expect("SpotMarket[0].insurance_fund.vault equals the derived "
                      "insurance_fund_vault[0] PDA", m["ifVault"], CONTROL_VAULT)
        checks.expect("SpotMarket[0] decodes its own market_index as 0",
                      m["marketIndex"], CONTROL_INDEX)
        # -- 16. online: offset sensitivity against a REAL account, not a
        #        synthetic buffer. total_shares read at the pinned offset must
        #        be non-zero AND must differ from the same width read eight
        #        bytes away. A layout that reported the same number wherever
        #        you looked would be reading noise.
        real = base64.b64decode(acc["data"][0])
        lo_o, hi_o = SM["if_total_shares"]
        at = int.from_bytes(real[lo_o:hi_o], "little")
        off = int.from_bytes(real[lo_o + 8:hi_o + 8], "little")
        checks.expect_true(
            "on the live control market, total_shares at the pinned offset is "
            "non-zero and differs from a read 8 bytes away",
            at > 0 and at != off,
            f"at offset {lo_o}: {at:,}; at offset {lo_o + 8}: {off:,}")
    except lib.CheckerError as exc:
        checks.blocked("live SpotMarket decode control", str(exc))

    checks.print_report()
    return checks.exit_code()


# ---------------------------------------------------------------------------

def run(program, seed, lo, hi, authority_seed=None, expect_nonempty=False,
        outflow=0, url=None, json_path=None, source_note=None) -> int:
    checks = lib.Checks()
    lib.banner(f"vault census: {seed.decode()}[{lo}..{hi - 1}] under {program}",
               url=lib.mask_url(url or lib.rpc_url()))
    if source_note:
        print(f"  seeds pinned to: {source_note}\n")

    derived = []
    for i in range(lo, hi):
        addr, bump = derive_vault(program, seed, i)
        derived.append({"index": i, "address": addr, "bump": bump})

    off_curve_bad = [d["address"] for d in derived
                     if lib.is_on_curve(lib.b58decode(d["address"]))]
    checks.expect_true(
        "every derived vault address is off the ed25519 curve",
        not off_curve_bad, f"on curve: {off_curve_bad}" or "all off-curve")

    expected_auth = None
    if authority_seed:
        expected_auth, abump = derive_authority(program, authority_seed)
        print(f"  authority PDA re-derived from seed "
              f"{authority_seed.decode()!r}: {expected_auth} (bump {abump})\n")

    # Fetch in batches; getMultipleAccounts caps at 100 per call.
    values = []
    addrs = [d["address"] for d in derived]
    for k in range(0, len(addrs), 50):
        chunk = lib.rpc("getMultipleAccounts",
                        [addrs[k:k + 50], {"encoding": "jsonParsed"}],
                        url=url)["value"]
        values.extend(chunk)

    live, missing, empty, funded = [], [], [], []
    for d, acc in zip(derived, values):
        if acc is None:
            d["exists"] = False
            missing.append(d)
            continue
        d["exists"] = True
        d.update(parse_token_account(d["address"], acc))
        live.append(d)
        (empty if d["amountRaw"] == 0 else funded).append(d)

    print(f"  derived {len(derived)} vault addresses")
    print(f"  {len(live)} exist on chain, {len(missing)} do not")
    print(f"  {len(funded)} hold a non-zero balance, {len(empty)} read ZERO\n")

    if expected_auth:
        wrong = [d for d in live if d["authority"] != expected_auth]
        checks.expect_true(
            "every live vault's authority is the program's own signer PDA",
            not wrong,
            f"{len(wrong)} vaults have a different authority: "
            f"{[(d['index'], d['authority']) for d in wrong][:5]}"
            if wrong else f"all {len(live)} name {expected_auth}")

    for d in live:
        flag = "  <-- ZERO" if d["amountRaw"] == 0 else ""
        print(f"  [{d['index']:3d}] {d['address']}  mint {d['mint']}  "
              f"{d['amountUi']:>24}{flag}")
    print()

    if expect_nonempty:
        checks.expect_true(
            "every live vault holds a non-zero balance",
            not empty,
            f"{len(empty)} of {len(live)} live vaults hold nothing "
            f"(indices {[d['index'] for d in empty][:20]}"
            f"{'...' if len(empty) > 20 else ''})")

    if outflow:
        print(f"  walking history for the last outflow from each empty vault "
              f"(up to {outflow} transactions each)\n")
        for d in empty:
            try:
                d["outflowWalk"] = find_last_outflow(d["address"],
                                                     max_tx=outflow, url=url)
            except lib.CheckerError as exc:
                print(f"  [{d['index']:3d}] history unavailable: {exc}")
                d["outflowWalk"] = {"found": False, "error": str(exc)}
                continue
            o = d["outflowWalk"]
            if not o.get("found"):
                print(f"  [{d['index']:3d}] {d['address']}: {o.get('note') or o.get('error')}")
                continue
            dec = d["decimals"]
            print(f"  [{d['index']:3d}] {d['address']}  mint {d['mint']}")
            for ev in o["outflows"]:
                out = ev["amountRawOut"] / (10 ** dec)
                print(f"        -{out:,.{dec}f}  {ev['when']}  {ev['signature']}")
                print(f"          signers:  {ev['signers']}")
                print(f"          programs: {ev['programs']}")
                for g in ev["creditedTo"]:
                    print(f"          -> {g['account']} (owner {g['owner']}) "
                          f"+{g['delta'] / (10 ** dec):,.{dec}f}")
            print()

    if json_path:
        Path(json_path).write_text(json.dumps({
            "checkedAt": lib.utc_now(),
            "program": program,
            "seed": seed.decode(),
            "indexRange": [lo, hi - 1],
            "authoritySeed": authority_seed.decode() if authority_seed else None,
            "expectedAuthority": expected_auth,
            "sourceNote": source_note,
            "vaults": derived,
        }, indent=2, default=str))
        print(f"  findings written to {json_path}\n")

    checks.print_report()
    return checks.exit_code()


def share_census(program, vault_seed, market_seed, lo, hi, market_account,
                 stake_account, stakers=False, url=None, json_path=None,
                 source_note=None) -> int:
    """The depositor side: who is still recorded as owning the fund?

    Reads three things and puts them next to each other:

      1. the vault balance         — what is actually there
      2. total_shares/user_shares  — what the protocol's books say is owed
      3. every individual stake    — who specifically the books say it is owed to

    and then applies the protocol's own redemption formula to turn (2) into a
    payout figure against (1). A claim of "depositors' assets are intact" is
    about all three; checking only the first cannot distinguish an empty fund
    that was paid out from an empty fund that was not.
    """
    checks = lib.Checks()
    lib.banner(
        f"share census: {market_seed.decode()}[{lo}..{hi - 1}] under {program}",
        url=lib.mask_url(url or lib.rpc_url()))
    if source_note:
        print(f"  layout pinned to: {source_note}\n")

    market_disc = lib.anchor_discriminator(market_account)
    stake_disc = lib.anchor_discriminator(stake_account)
    print(f"  {market_account} discriminator: {market_disc.hex()}")
    print(f"  {stake_account} discriminator: {stake_disc.hex()}\n")

    # ---- derive both families of address independently -------------------
    market_addrs, vault_addrs = [], []
    for i in range(lo, hi):
        m, _ = lib.find_program_address([market_seed, index_seed(i)],
                                        lib.parse_pubkey(program))
        market_addrs.append(lib.b58encode(m))
        vault_addrs.append(derive_vault(program, vault_seed, i)[0])

    # ---- read them -------------------------------------------------------
    m_raw = []
    for s in range(0, len(market_addrs), 100):
        m_raw.extend(lib.rpc("getMultipleAccounts",
                             [market_addrs[s:s + 100], {"encoding": "base64"}],
                             url=url)["value"])
    v_raw = []
    for s in range(0, len(vault_addrs), 100):
        v_raw.extend(lib.rpc("getMultipleAccounts",
                             [vault_addrs[s:s + 100],
                              {"encoding": "jsonParsed"}], url=url)["value"])

    markets, missing = [], []
    for n, (addr, acc) in enumerate(zip(market_addrs, m_raw)):
        idx = lo + n
        if acc is None:
            missing.append(idx)
            continue
        m = decode_spot_market(addr, acc, market_disc)
        m["derivedIndex"] = idx
        m["derivedVault"] = vault_addrs[n]
        vacc = v_raw[n]
        m["vaultBalance"] = (None if vacc is None
                             else parse_token_account(vault_addrs[n], vacc)["amountRaw"])
        markets.append(m)

    live = [m for m in markets if m["vaultBalance"] is not None]

    # ---- CONTROL: the layout has to predict something ---------------------
    # market_index is a field I know the value of BEFORE reading the account,
    # because I derived the address from it. If the offsets were wrong this
    # would be garbage for all 64. It cannot be faked by a lucky run of zeros.
    bad_index = [(m["derivedIndex"], m["marketIndex"]) for m in markets
                 if m["marketIndex"] != m["derivedIndex"]]
    checks.expect_true(
        "every decoded market_index equals the index its address was derived "
        "from (the struct offsets are right)",
        not bad_index,
        f"mismatches: {bad_index}" if bad_index
        else f"all {len(markets)} agree")

    # CONTROL: the account says its own address, at a second offset.
    bad_self = [m["address"] for m in markets
                if m["declaredPubkey"] != m["address"]]
    checks.expect_true(
        "every market's stored `pubkey` field equals its own derived address",
        not bad_self,
        f"mismatches: {bad_self}" if bad_self else f"all {len(markets)} agree")

    # CONTROL: the two independent derivations meet. The vault address I
    # derived from the seed string equals the vault address the market
    # account names in its own InsuranceFund struct. This is what ties the
    # ledger side to the balance side; without it they are two unrelated lists.
    bad_vault = [(m["derivedIndex"], m["ifVault"], m["derivedVault"])
                 for m in markets if m["ifVault"] != m["derivedVault"]]
    checks.expect_true(
        "each market's insurance_fund.vault field equals the "
        "independently derived insurance_fund_vault PDA",
        not bad_vault,
        f"mismatches: {bad_vault}" if bad_vault
        else f"all {len(markets)} agree")

    if missing:
        checks.observe("market indices with no account", missing)

    # ---- the finding -----------------------------------------------------
    print(f"  {len(markets)} of {hi - lo} market accounts exist; "
          f"{len(live)} have a readable vault\n")
    print(f"  {'idx':>3}  {'name':<16} {'vault balance':>22}  "
          f"{'user_shares':>24}  {'redeems for':>16}")
    print("  " + "-" * 88)

    credited, backed = [], []
    for m in live:
        dec = m["decimals"]
        redeem = if_shares_to_vault_amount(m["userShares"], m["totalShares"],
                                           m["vaultBalance"])
        m["userSharesRedeemRaw"] = redeem
        if m["userShares"] > 0:
            credited.append(m)
        if m["vaultBalance"] > 0:
            backed.append(m)
        if m["userShares"] == 0 and m["vaultBalance"] == 0:
            continue
        print(f"  {m['derivedIndex']:>3}  {m['name'][:16]:<16} "
              f"{m['vaultBalance'] / (10 ** dec):>22,.{dec}f}  "
              f"{m['userShares']:>24,}  "
              f"{redeem / (10 ** dec):>16,.{dec}f}")

    dangling = [m for m in live
                if m["userShares"] > 0 and m["vaultBalance"] == 0]

    print()
    checks.observe("markets whose books still credit depositors with shares",
                   f"{len(credited)} of {len(live)}")
    checks.observe("markets whose insurance fund vault holds anything",
                   f"{len(backed)} of {len(live)}")
    checks.observe("markets with non-zero user_shares AND an empty vault "
                   "(recorded claim, no backing)",
                   f"{len(dangling)} of {len(live)}")
    checks.observe("total redemption value of ALL depositor shares, "
                   "every market, by the protocol's own formula",
                   sum(m["userSharesRedeemRaw"] for m in live))

    # ---- the individual depositors ---------------------------------------
    stake_rows = []
    if stakers:
        print("  censusing individual depositor stake accounts "
              "(getProgramAccounts)...")
        try:
            got = lib.rpc("getProgramAccounts", [program, {
                "encoding": "base64",
                "filters": [{"dataSize": IF_STAKE_LEN},
                            {"memcmp": {"offset": 0,
                                        "bytes": lib.b58encode(stake_disc)}}],
            }], url=url, timeout=180)
            for entry in got:
                stake_rows.append(decode_if_stake(
                    entry["pubkey"],
                    base64.b64decode(entry["account"]["data"][0]),
                    stake_disc))
        except lib.CheckerError as exc:
            checks.blocked("individual depositor census", str(exc))

    if stake_rows:
        by_market = {}
        for s in stake_rows:
            by_market.setdefault(s["marketIndex"], []).append(s)
        nonzero = [s for s in stake_rows if s["ifShares"] > 0]
        print(f"  {len(stake_rows):,} stake accounts exist; "
              f"{len(nonzero):,} hold non-zero shares\n")

        # CONTROL: the individual accounts have to add up to the aggregate the
        # market publishes. Two separately-decoded structs, read from
        # different accounts, with different layouts, agreeing on a number
        # neither one can see. If either layout were wrong this fails.
        #
        # `if_base` is a rebase exponent: a stake's shares are only comparable
        # to the market's total when stake.if_base == market.shares_base
        # (state/insurance_fund_stake.rs, validate_base). Stale-base stakes
        # are rescaled by 10^(market_base - stake_base), which is what the
        # program itself does before touching them.
        agree, disagree, stale = [], [], 0
        for m in live:
            total = 0
            for s in by_market.get(m["derivedIndex"], []):
                shares = s["ifShares"]
                if s["ifBase"] != m["sharesBase"]:
                    stale += 1
                    if s["ifBase"] < m["sharesBase"]:
                        shares //= 10 ** (m["sharesBase"] - s["ifBase"])
                    else:
                        continue
                total += shares
            rows_here = by_market.get(m["derivedIndex"], [])
            m["stakeSumShares"] = total
            m["stakeAccounts"] = len(rows_here)
            m["stakeAccountsNonZero"] = sum(1 for s in rows_here
                                            if s["ifShares"] > 0)
            (agree if total == m["userShares"] else disagree).append(
                (m["derivedIndex"], total, m["userShares"]))

        checks.expect_true(
            "the sum of individual depositor stake accounts reconciles to the "
            "user_shares each market publishes",
            not disagree,
            f"{len(agree)} markets reconcile exactly; mismatches "
            f"(index, sum, published): {disagree[:6]}" if disagree
            else f"all {len(agree)} markets reconcile exactly")
        checks.observe("stake accounts on a stale rebase base", stale)

        # When were these records last touched? `last_valid_ts` is written on
        # every stake operation. If the depositor records were reconciled
        # after the fund left, that shows up here as activity. If they were
        # simply left as they were, that shows up too.
        EXPLOIT_TS = 1774915200   # 2026-04-01T00:00:00Z, the day of the exploit
        touched = [s for s in nonzero if s["lastValidTs"] >= EXPLOIT_TS]
        checks.observe(
            "depositor records with non-zero shares last touched ON OR AFTER "
            "2026-04-01 (the exploit)",
            f"{len(touched):,} of {len(nonzero):,}")
        if nonzero:
            newest = max(s["lastValidTs"] for s in nonzero)
            checks.observe("most recent last_valid_ts across all non-zero "
                           "depositor records", f"{newest} ({utc(newest)})")

        checks.observe("distinct depositor authorities holding non-zero shares",
                       f"{len({s['authority'] for s in nonzero}):,}")

        holders_dangling = sorted(
            (s for s in nonzero
             if any(m["derivedIndex"] == s["marketIndex"] and
                    m["vaultBalance"] == 0 for m in live)),
            key=lambda s: -s["ifShares"])
        checks.observe("individual depositors holding non-zero shares in a "
                       "market whose vault is empty", len(holders_dangling))
        if holders_dangling:
            print("  largest recorded holdings that redeem for zero:")
            for s in holders_dangling[:5]:
                print(f"    {s['authority']}  market {s['marketIndex']:>2}  "
                      f"{s['ifShares']:>24,} shares  -> 0")
            print()

    # ---- the assertion the claim actually rests on ------------------------
    # Stated so that it FAILS when depositors are not intact. A checker whose
    # assertions all pass no matter what the chain says is decoration.
    checks.expect_true(
        "every depositor share balance is redeemable for a non-zero amount "
        "(i.e. depositors' recorded assets are backed)",
        not dangling,
        f"{len(dangling)} markets credit depositors with shares against an "
        f"empty vault: indices {[m['derivedIndex'] for m in dangling]}"
        if dangling else "no market has shares without backing")

    print("\nOBSERVED")
    print("-" * 70)
    for row in checks.rows:
        if row["kind"] == "observed":
            print(f"  {row['label']}:\n      {row['found']}")

    if json_path:
        Path(json_path).write_text(json.dumps({
            "checkedAt": lib.utc_now(),
            "program": program,
            "marketSeed": market_seed.decode(),
            "vaultSeed": vault_seed.decode(),
            "indexRange": [lo, hi - 1],
            "sourceNote": source_note,
            "marketDiscriminator": market_disc.hex(),
            "stakeDiscriminator": stake_disc.hex(),
            "markets": markets,
            "stakeAccountCount": len(stake_rows),
            "stakeAccountsNonZero": sum(1 for s in stake_rows
                                        if s["ifShares"] > 0),
            "stakeAccounts": sorted(stake_rows, key=lambda s: -s["ifShares"])[:200]
            if stake_rows else [],
        }, indent=2, default=str))
        print(f"  findings written to {json_path}\n")

    checks.print_report()
    return checks.exit_code()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--preset", choices=sorted(PRESETS))
    p.add_argument("--program")
    p.add_argument("--seed")
    p.add_argument("--index-range", default=None,
                   help="inclusive:exclusive, e.g. 0:64")
    p.add_argument("--authority-seed", default=None)
    p.add_argument("--expect-nonempty", action="store_true",
                   help="assert every live vault holds something (exit 1 if not)")
    p.add_argument("--outflow", type=int, nargs="?", const=10, default=0,
                   help="for each empty vault, walk up to N transactions back "
                        "to find what emptied it")
    p.add_argument("--shares", action="store_true",
                   help="census the DEPOSITOR side: share accounting per "
                        "market, and what those shares redeem for")
    p.add_argument("--stakers", action="store_true",
                   help="with --shares, also census every individual "
                        "depositor stake account")
    p.add_argument("--rpc", default=None)
    p.add_argument("--json", default=None)
    p.add_argument("--self-test", action="store_true")
    args = p.parse_args(argv)

    if args.self_test:
        return self_test(url=args.rpc)

    source_note = None
    if args.preset:
        cfg = PRESETS[args.preset]
        program = args.program or cfg["program"]
        seed = args.seed.encode() if args.seed else cfg["seed"]
        lo, hi = cfg["index_range"]
        auth_seed = (args.authority_seed.encode() if args.authority_seed
                     else cfg["authority_seed"])
        source_note = cfg["source"]
    else:
        if not (args.program and args.seed):
            p.error("give --preset, or both --program and --seed")
        program = args.program
        seed = args.seed.encode()
        lo, hi = 0, 64
        auth_seed = args.authority_seed.encode() if args.authority_seed else None

    if args.index_range:
        try:
            lo, hi = (int(x) for x in args.index_range.split(":"))
        except ValueError:
            p.error("--index-range wants lo:hi, e.g. 0:64")

    try:
        if args.shares:
            cfg = PRESETS[args.preset]["shares"] if args.preset else None
            if cfg is None:
                p.error("--shares needs a --preset that declares a share "
                        "layout; only accounts whose struct is pinned to the "
                        "project's own source can be decoded safely")
            return share_census(program, seed, cfg["market_seed"], lo, hi,
                                cfg["market_account"], cfg["stake_account"],
                                stakers=args.stakers, url=args.rpc,
                                json_path=args.json,
                                source_note=cfg["source"])
        return run(program, seed, lo, hi, authority_seed=auth_seed,
                   expect_nonempty=args.expect_nonempty, outflow=args.outflow,
                   url=args.rpc, json_path=args.json, source_note=source_note)
    except lib.CheckerError as exc:
        print(f"\nCOULD NOT CHECK: {exc}\n", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
