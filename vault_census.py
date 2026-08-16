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
    },
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
        return run(program, seed, lo, hi, authority_seed=auth_seed,
                   expect_nonempty=args.expect_nonempty, outflow=args.outflow,
                   url=args.rpc, json_path=args.json, source_note=source_note)
    except lib.CheckerError as exc:
        print(f"\nCOULD NOT CHECK: {exc}\n", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
