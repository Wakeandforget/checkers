#!/usr/bin/env python3
"""
multisig.py — check who really controls a Squads multisig wallet.

CLAIM CLASS: "the treasury is in a N-of-M multisig" — thresholds, member
lists, member permissions, the vault address, the config authority and the
time lock of a Squads multisig on Solana mainnet. Both Squads v4 and the
older Squads v3 (squads-mpl) are decoded; the version is detected from the
account's owner, never guessed.

SECOND CLAIM CLASS: "program X is upgradeable only by our multisig". Pass
--expect-controls-program X and this script resolves X's on-chain upgrade
authority, re-derives the multisig's signing PDA from first principles, and
asserts the two are the same account. That turns a sentence in a docs page
into arithmetic anyone can repeat.

RUN: python3 checkers/multisig.py <MULTISIG_ADDRESS> --expect-threshold 3 --expect-members 5

What this answers
-----------------
A project says "our treasury is in a 3-of-5 multisig". That sentence contains
several separate claims, and they fail in different ways:

  * the threshold really is 3        (not 1, which would mean one person can move everything)
  * there really are 5 members       (not 5 listed and 7 on chain)
  * the money is where they say      (the vault address is re-derived here, from
                                      the multisig address and the program id, so
                                      we never take an explorer's word for it)
  * nobody can rewrite the rules     (a "config authority", if set, is an account
                                      that can change members and threshold
                                      WITHOUT a vote — it quietly undoes the whole
                                      arrangement, and almost nobody checks it)
  * the time lock                    (a delay between approval and execution)

Everything is decoded from the raw account bytes. No SDK, no explorer API, no
credentials.

Exit codes
----------
  0  every assertion held
  1  at least one assertion is false
  2  it could not be checked (network, bad address, not a Squads account)
"""

import argparse
import json
import sys
from pathlib import Path

# Allow both "python3 checkers/multisig.py" and "python3 -m checkers.multisig"
# to find _lib.py, whichever directory the reader happens to be standing in.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import _lib as lib  # noqa: E402
# Reused, not reimplemented: spl_mint already decodes the BPF Upgradeable
# Loader's Program and ProgramData records byte by byte. A second copy of that
# decoder here would be a second thing to get wrong.
import spl_mint  # noqa: E402

# ---------------------------------------------------------------------------
# Facts about Squads v4 itself
# ---------------------------------------------------------------------------

# The on-chain program that owns every Squads v4 multisig account.
SQUADS_PROGRAM = "SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf"

# Squads v3 ("squads-mpl"). Still holds real money and real program upgrade
# authorities — a great many 2023-era deployments never migrated to v4. A
# checker that only understands v4 will look at a live v3 multisig and report
# "this is not a Squads multisig", which is a wrong answer, not a safe one.
SQUADS_V3_PROGRAM = "SMPLecH534NA9acpos4G6x7uf3LWbCAwZQE9e8ZekMu"

# Which owner means which layout. Nothing is inferred from the address itself.
SQUADS_PROGRAMS = {SQUADS_PROGRAM: "v4", SQUADS_V3_PROGRAM: "v3"}

# A member's permissions are a bitmask: one bit per power.
#   1 Initiate — may propose a transaction
#   2 Vote     — may approve or reject one
#   4 Execute  — may push an already-approved transaction through
# A member with Vote but not Execute still counts toward the threshold.
PERMISSION_BITS = [(1, "Initiate"), (2, "Vote"), (4, "Execute")]


def decode_permissions(mask: int) -> list:
    """Turn a permission bitmask into names, e.g. 7 -> [Initiate, Vote, Execute]."""
    names = [name for bit, name in PERMISSION_BITS if mask & bit]
    # Bits above the three known ones mean this program version has powers this
    # script does not understand. Say so rather than quietly reporting fewer.
    unknown = mask & ~0b111
    if unknown:
        names.append(f"UNKNOWN(bits {unknown:#b})")
    return names


def decode_multisig(data: bytes) -> dict:
    """Decode a Squads v4 Multisig account from its raw bytes.

    The field order below is the account layout. Each field follows the last
    with no padding, which is why they must be read in exactly this order.
    Cursor refuses to read past the end of the data, so a wrong guess about the
    layout produces a loud error instead of plausible nonsense.
    """
    cursor = lib.Cursor(data, label="Multisig")

    # The 8-byte tag proving this is a Multisig account and not something else
    # that happens to live at this address. If this raises, stop: nothing below
    # it would mean anything.
    cursor.expect_discriminator("Multisig")

    decoded = {
        "createKey": cursor.pubkey(),            # one-off key used to create it
        "configAuthority": cursor.pubkey(),      # can rewrite the rules, if set
        "threshold": cursor.u16(),               # signatures needed to execute
        "timeLock": cursor.u32(),                # seconds between approval and execution
        "transactionIndex": cursor.u64(),        # how many transactions ever proposed
        "staleTransactionIndex": cursor.u64(),   # everything below this is void
        "rentCollector": cursor.option_pubkey(),
        "bump": cursor.u8(),
    }

    # Then the member list: a 4-byte count, then that many (32-byte key + 1-byte
    # permission mask) pairs.
    member_count = cursor.u32()
    if member_count > 10_000:
        raise lib.CheckerError(
            f"member count reads as {member_count}, which is absurd. The layout "
            "assumed here does not match this account."
        )
    members = []
    for _ in range(member_count):
        key = cursor.pubkey()
        mask = cursor.u8()
        members.append({
            "key": key,
            "mask": mask,
            "permissions": decode_permissions(mask),
        })
    decoded["members"] = members
    decoded["trailingBytes"] = cursor.remaining
    return decoded


def decode_multisig_v3(data: bytes) -> dict:
    """Decode a Squads v3 (squads-mpl) `Ms` account from its raw bytes.

    Layout, from the published program source — `programs/squads-mpl/src/state.rs`,
    `pub struct Ms` — read in this exact order with no padding:

        u16  threshold          signatures needed to execute
        u16  authority_index    how many authority PDAs have been handed out
        u32  transaction_index  transactions proposed to date
        u32  ms_change_index    everything proposed below this is void
        u8   bump               bump of the multisig PDA itself
        [32] create_key         the key this multisig's address was seeded from
        u8   allow_external_execute  (deprecated flag)
        vec<[32]> keys          the members

    v3 differs from v4 in two ways that matter to a reader and that this
    function must not paper over:

      * There are no per-member permission masks. Every member may propose,
        approve and execute. So "members who can actually vote" is always the
        whole list, not a subset.
      * There is no config-authority field. In v4 a config authority can
        rewrite the member list without a vote; in v3 that account cannot
        exist, so members and threshold can only change through a multisig
        transaction. That is a genuine structural difference, not an omission.
    """
    cursor = lib.Cursor(data, label="Ms(v3)")
    cursor.expect_discriminator("Ms")

    decoded = {
        "threshold": cursor.u16(),
        "authorityIndex": cursor.u16(),
        "transactionIndex": cursor.u32(),
        "changeIndex": cursor.u32(),
        "bump": cursor.u8(),
        "createKey": cursor.pubkey(),
        "allowExternalExecute": bool(cursor.u8()),
    }

    member_count = cursor.u32()
    if member_count > 10_000:
        raise lib.CheckerError(
            f"member count reads as {member_count}, which is absurd. The layout "
            "assumed here does not match this account."
        )
    # v3 has no permission bitmask. Rather than invent a mask, say what the
    # program actually enforces: uniform powers for every member.
    decoded["members"] = [
        {"key": cursor.pubkey(), "mask": None,
         "permissions": ["Initiate", "Vote", "Execute"]}
        for _ in range(member_count)
    ]
    decoded["configAuthority"] = None       # cannot exist in v3
    decoded["timeLock"] = None              # not a v3 feature
    decoded["trailingBytes"] = cursor.remaining
    return decoded


def derive_authority_v3(multisig_address: str, authority_index: int = 1):
    """Re-derive a Squads v3 authority ("vault") PDA from first principles.

    Seeds are ["squad", <multisig address>, <authority index as u32 LE>,
    "authority"], per the published program source. Index 1 is the default
    vault: `Ms::init` sets `authority_index = 1` with the comment "default
    vault is the first authority".

    Note the seed order differs from v4, and the index is a 4-byte little
    endian integer here rather than v4's single byte. Getting either wrong
    produces a different address, which is exactly why this is re-derived
    rather than copied from an explorer.

    Returns (address, bump).
    """
    if not 0 <= authority_index <= 0xFFFFFFFF:
        raise lib.CheckerError("authority index must fit in a u32")
    raw, bump = lib.find_program_address(
        [
            b"squad",
            lib.parse_pubkey(multisig_address),
            authority_index.to_bytes(4, "little"),
            b"authority",
        ],
        lib.parse_pubkey(SQUADS_V3_PROGRAM),
    )
    return lib.b58encode(raw), bump


def derive_multisig_v3(create_key: str):
    """Re-derive a v3 multisig's own address from its stored create_key.

    Seeds ["squad", <create_key>, "multisig"]. This is a free consistency
    check: if an account claims a create_key that does not hash back to the
    address the account was found at, the bytes are not what they appear.
    """
    raw, bump = lib.find_program_address(
        [b"squad", lib.parse_pubkey(create_key), b"multisig"],
        lib.parse_pubkey(SQUADS_V3_PROGRAM),
    )
    return lib.b58encode(raw), bump


def derive_signer(multisig_address: str, version: str, index: int):
    """The one address that signs on this multisig's behalf, for either version."""
    if version == "v4":
        return derive_vault(multisig_address, index)
    return derive_authority_v3(multisig_address, index)


def derive_vault(multisig_address: str, vault_index: int = 0):
    """Work out the vault address ourselves, from first principles.

    The vault is a Program Derived Address: its address is a hash of the seeds
    ["multisig", <multisig address>, "vault", <index>] and the Squads program
    id. Because we recompute it, an explorer showing a different "treasury"
    address is a discrepancy this script will catch rather than inherit.

    Returns (address, bump).
    """
    if not 0 <= vault_index <= 255:
        raise lib.CheckerError("vault index must be between 0 and 255")
    raw, bump = lib.find_program_address(
        [
            b"multisig",
            lib.parse_pubkey(multisig_address),
            b"vault",
            bytes([vault_index]),
        ],
        lib.parse_pubkey(SQUADS_PROGRAM),
    )
    return lib.b58encode(raw), bump


def resolve_program_control(program_id: str, signer_address: str, url=None) -> dict:
    """Is `program_id` upgradeable by `signer_address`, and nothing else?

    Answers the question a docs page raises when it says "Upgrade Authority:
    Our Multisig". Three separate things can go wrong and are reported apart:

      * the program is not upgradeable at all (old loader, or authority
        already revoked) — then no multisig controls it, and saying it does
        is wrong even though it is wrong in a reassuring direction;
      * it is upgradeable, but by some other account;
      * it is upgradeable by exactly the account given.

    Returns a dict; the caller decides what is a pass.
    """
    info = spl_mint.program_upgrade_authority(program_id, url=url)
    authority = info.get("upgradeAuthority")
    return {
        "programId": program_id,
        "programDataAddress": info.get("programDataAddress"),
        "lastDeployedSlot": info.get("lastDeployedSlot"),
        "upgradeAuthority": authority,
        "expectedAuthority": signer_address,
        "immutable": authority is None,
        "controlled": authority is not None and authority == signer_address,
    }


def find_multisig_for_authority(authority_address: str, version: str = "v3",
                                max_index: int = 4, url=None, progress=None):
    """Search for the multisig whose signing PDA is `authority_address`.

    A PDA cannot be inverted — it is a hash. So the only honest way to get
    from "this account is the upgrade authority" back to "and this multisig
    controls it" is to enumerate every multisig the Squads program owns and
    re-derive each one's signing PDA until one matches.

    This is deliberately the slow path. It is how a claim is DISCOVERED. Once
    the answer is known, a reader verifies it in milliseconds by deriving in
    the forward direction instead — which is what --expect-controls-program
    does. Discovery is expensive; verification is not.

    Requires getProgramAccounts, which some public endpoints refuse.
    """
    program = SQUADS_PROGRAM if version == "v4" else SQUADS_V3_PROGRAM
    account_name = "Multisig" if version == "v4" else "Ms"
    discriminator = lib.anchor_discriminator(account_name)

    try:
        found = lib.rpc(
            "getProgramAccounts",
            [program, {"encoding": "base64",
                       "dataSlice": {"offset": 0, "length": 0},
                       "filters": [{"memcmp": {"offset": 0,
                                               "bytes": lib.b58encode(discriminator)}}]}],
            url=url, timeout=120)
    except lib.CheckerError as exc:
        raise lib.CheckerError(
            f"could not enumerate Squads {version} accounts: {exc}. Many public "
            "RPC endpoints disable getProgramAccounts; retry with --rpc pointing "
            "at one that allows it."
        ) from exc

    candidates = [entry["pubkey"] for entry in found]
    for index in range(0, max_index + 1):
        for position, candidate in enumerate(candidates):
            try:
                derived, bump = derive_signer(candidate, version, index)
            except lib.CheckerError:
                continue
            if derived == authority_address:
                return {"multisig": candidate, "version": version,
                        "index": index, "bump": bump,
                        "searched": len(candidates)}
            if progress and position and position % 25000 == 0:
                progress(index, position, len(candidates))
    return None


def describe_timelock(seconds: int) -> str:
    """'0' is a fine answer but a bare number is not a readable one."""
    if seconds == 0:
        return "0 seconds (no time lock — an approved transaction can execute at once)"
    if seconds < 3600:
        return f"{seconds} seconds ({seconds / 60:.0f} minutes)"
    if seconds < 86400:
        return f"{seconds} seconds ({seconds / 3600:.1f} hours)"
    return f"{seconds} seconds ({seconds / 86400:.1f} days)"


# ---------------------------------------------------------------------------
# The check itself
# ---------------------------------------------------------------------------


def check(address, expect_threshold=None, expect_members=None, vault_index=None,
          expect_controls_programs=None, url=None, quiet=False):
    """Run the whole check. Returns (Checks, facts-dict).

    Raises CheckerError if it could not get far enough to assert anything —
    the caller turns that into exit code 2, never into a pass.
    """
    out = sys.stderr if quiet else sys.stdout
    checks = lib.Checks()

    if not quiet:
        lib.banner(f"SQUADS MULTISIG CHECK — {address}", url=url, stream=out)

    # --- 1. fetch and confirm what kind of account this is ------------------
    account = lib.get_account(address, url=url)

    # If this is not owned by a Squads program then it is not a Squads
    # multisig, whatever anyone calls it. Assert rather than assume.
    version = SQUADS_PROGRAMS.get(account["owner"])
    checks.expect_true(
        "the account is owned by a Squads program (v4 or v3)",
        version is not None,
        f"owner is {account['owner']}"
        + (f" — Squads {version}" if version else " — not a Squads program"),
    )
    if version is None:
        # Decoding foreign bytes with the Squads layout would produce garbage
        # that looks like data. Stop here and say why.
        raise lib.CheckerError(
            f"{address} is owned by {account['owner']}, which is neither the "
            f"Squads v4 program ({SQUADS_PROGRAM}) nor the Squads v3 program "
            f"({SQUADS_V3_PROGRAM}). This is not a Squads multisig account."
        )

    if version == "v4":
        multisig = decode_multisig(account["data"])
        # v4 vaults are indexed from 0.
        signer_index = 0 if vault_index is None else vault_index
    else:
        multisig = decode_multisig_v3(account["data"])
        # v3's default vault is authority index 1, not 0. Defaulting to 0 here
        # would derive a real-looking address that holds nothing.
        signer_index = 1 if vault_index is None else vault_index

    # --- 2. report the facts -----------------------------------------------
    vault_address, vault_bump = derive_signer(address, version, signer_index)
    config_authority = multisig["configAuthority"]
    # In v3 the field cannot exist; in v4, "unset" is written as the system program.
    authority_is_none = (config_authority is None
                         or config_authority == lib.SYSTEM_PROGRAM)

    if not quiet:
        print(f"  squads version     {version}", file=out)
        print(f"  threshold          {multisig['threshold']} of {len(multisig['members'])}",
              file=out)
        print(f"  members            {len(multisig['members'])}", file=out)
        if multisig["timeLock"] is None:
            print("  time lock          n/a — Squads v3 has no time lock feature",
                  file=out)
        else:
            print(f"  time lock          {describe_timelock(multisig['timeLock'])}",
                  file=out)
        if config_authority is None:
            print("  config authority   n/a — Squads v3 has no config-authority field, "
                  "so members\n                     and threshold can only change "
                  "through a multisig transaction", file=out)
        else:
            print(f"  config authority   "
                  f"{'none — members and threshold can only change by a vote' if authority_is_none else config_authority}",
                  file=out)
        if config_authority is not None and not authority_is_none:
            print("                     ^ THIS ACCOUNT CAN CHANGE THE MEMBERS AND THE",
                  file=out)
            print("                       THRESHOLD WITHOUT A VOTE.", file=out)
        label = "vault" if version == "v4" else "authority"
        print(f"  {label} (index {signer_index})  {vault_address}  (bump {vault_bump})",
              file=out)
        print(f"                     re-derived here, not read from an explorer",
              file=out)
        print(f"  transactions       {multisig['transactionIndex']} proposed to date",
              file=out)
        print(f"  account            {account['lamports']} lamports of rent, "
              f"{len(account['data'])} bytes", file=out)
        print("", file=out)
        print("  MEMBERS", file=out)
        for member in multisig["members"]:
            if member["mask"] is None:
                print(f"    {member['key']}  (v3: every member may propose, "
                      f"vote and execute)", file=out)
            else:
                print(f"    {member['key']}  mask={member['mask']} "
                      f"{'+'.join(member['permissions']) or 'NO PERMISSIONS'}", file=out)

    checks.observe("squads version", version)
    checks.observe("threshold", multisig["threshold"])
    checks.observe("member count", len(multisig["members"]))
    checks.observe("signer PDA (derived)", vault_address)
    checks.observe("config authority",
                   "n/a (v3 has no such field)" if config_authority is None
                   else config_authority)
    checks.observe("time lock (seconds)",
                   "n/a (v3 has no time lock)" if multisig["timeLock"] is None
                   else multisig["timeLock"])

    # --- 3. structural assertions, made on every run ------------------------
    # These hold for any honest Squads multisig, so they are checked whether or
    # not the caller passed an --expect flag. They are what makes a bare run
    # with no flags still mean something.
    checks.expect_true(
        "the vault address is off the ed25519 curve, so no private key for it "
        "can exist and only the multisig program can move its funds",
        not lib.is_on_curve(lib.b58decode(vault_address)),
        "derived address is not a valid ed25519 point",
    )
    checks.expect_true(
        "the threshold is at least 1 and no greater than the number of members "
        "(a threshold above the member count can never be met)",
        1 <= multisig["threshold"] <= len(multisig["members"]),
        f"threshold={multisig['threshold']}, members={len(multisig['members'])}",
    )
    # In v3 every member votes, so mask is None and the whole list counts.
    voters = [m for m in multisig["members"]
              if m["mask"] is None or m["mask"] & 2]
    checks.expect_true(
        "at least `threshold` members actually hold the Vote permission "
        "(members who cannot vote do not count toward the threshold)",
        len(voters) >= multisig["threshold"],
        f"{len(voters)} of {len(multisig['members'])} members can vote, "
        f"threshold is {multisig['threshold']}",
    )
    # Deliberately an observation, not an assertion. A 1-of-M really is a single
    # point of failure wearing the word "multisig", and a reader should see it
    # in capitals — but it is a true fact about the account, not a false claim,
    # and exit 1 in this project means "a claim is false", never "I disapprove".
    if multisig["threshold"] < 2:
        checks.observe("WARNING",
                       f"threshold is {multisig['threshold']} — ONE key can act "
                       f"alone; this is a multisig in name only")
        if not quiet:
            print("\n  *** WARNING: threshold is below 2. A single member can "
                  "execute\n      transactions unilaterally. ***", file=out)
    duplicate_keys = len(multisig["members"]) != len({m["key"] for m in multisig["members"]})
    checks.expect_true(
        "no address appears twice in the member list (a duplicate would let one "
        "signer count more than once)",
        not duplicate_keys,
        "all member addresses are distinct" if not duplicate_keys else "DUPLICATES FOUND",
    )

    # A v3 account stores the key its own address was seeded from. Hashing it
    # back must reproduce the address we fetched. This costs nothing and it
    # catches bytes that merely look like an Ms account.
    if version == "v3":
        rederived, rederived_bump = derive_multisig_v3(multisig["createKey"])
        checks.expect_true(
            "the multisig's own address re-derives from the create_key stored "
            "inside it (proves these bytes belong at this address)",
            rederived == address and rederived_bump == multisig["bump"],
            f"create_key {multisig['createKey']} -> {rederived} "
            f"(bump {rederived_bump}); account is {address} (stored bump "
            f"{multisig['bump']})",
        )
        checks.expect_true(
            "every byte of the account is accounted for by the assumed layout "
            "(no trailing slack that a wrong layout could be hiding in)",
            multisig["trailingBytes"] == 0,
            f"{multisig['trailingBytes']} bytes left over after decoding "
            f"{len(multisig['members'])} members",
        )

    # --- 4. the caller's assertions ----------------------------------------
    if expect_threshold is not None:
        checks.expect("the threshold is the claimed value",
                      multisig["threshold"], expect_threshold)
    if expect_members is not None:
        checks.expect("the number of members is the claimed value",
                      len(multisig["members"]), expect_members)

    # --- 5. "this multisig controls program X" ------------------------------
    # The forward direction: derive the signer PDA from the multisig, read the
    # program's upgrade authority off the chain, and require they be equal.
    controls = []
    for program_id in (expect_controls_programs or []):
        try:
            result = resolve_program_control(program_id, vault_address, url=url)
        except lib.CheckerError as exc:
            raise lib.CheckerError(
                f"could not resolve the upgrade authority of {program_id}: {exc}"
            ) from exc
        controls.append(result)

        if result["immutable"]:
            # Worth stating plainly: this is not the claimed arrangement, even
            # though "nobody can upgrade it" sounds safer than the claim.
            checks.expect_true(
                f"program {program_id} is upgradeable by this multisig",
                False,
                "the program has NO upgrade authority — it is immutable, so it "
                "is not controlled by this or any multisig",
            )
            continue
        checks.expect(
            f"program {program_id} names this multisig's signer PDA as its "
            f"upgrade authority",
            result["upgradeAuthority"],
            vault_address,
        )

    if controls and not quiet:
        print("", file=out)
        print("  PROGRAMS THIS MULTISIG WAS CLAIMED TO CONTROL", file=out)
        for result in controls:
            state = ("IMMUTABLE (no authority)" if result["immutable"]
                     else ("controlled" if result["controlled"]
                           else f"controlled by SOMEONE ELSE: {result['upgradeAuthority']}"))
            print(f"    {result['programId']}", file=out)
            print(f"      programData {result['programDataAddress']}", file=out)
            print(f"      last deploy slot {result['lastDeployedSlot']} — {state}",
                  file=out)

    facts = {
        "checkedAt": lib.utc_now(),
        "rpc": lib.mask_url(url or lib.rpc_url()),
        "multisigAddress": address,
        "squadsVersion": version,
        "squadsProgram": account["owner"],
        "owner": account["owner"],
        "vault": {"index": signer_index, "address": vault_address,
                  "bump": vault_bump},
        "configAuthority": None if authority_is_none else config_authority,
        "multisig": multisig,
        "programsControlled": controls,
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

# A real Squads v4 multisig on Solana mainnet: this project's own treasury.
# Chosen because its contents are published and independently verifiable, and
# because if it ever changes, this self-test failing is itself useful news.
KNOWN_MULTISIG = "7on6D7Ci3axhmaUMcxyLzUZuuTXaRuNZxmNogkY1UKja"
KNOWN_THRESHOLD = 2
KNOWN_MEMBERS = 3
KNOWN_VAULT = "G14wmiKKHnADNGPPpfvZywcbeDKqj97dKaFVHLUt5fdj"
KNOWN_VAULT_BUMP = 254

# An account that exists but is not a Squads multisig. Used to confirm the
# checker refuses to decode foreign bytes instead of inventing a threshold.
NOT_A_MULTISIG = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"  # SPL Token program

# A real Squads *v3* multisig: the one holding Sanctum's program upgrade
# authority, identified in wake 3 by exhaustive search and pinned here.
#
# The OFFLINE v3 controls below use only PDA arithmetic, which is deterministic
# and cannot rot: these addresses hash to each other today and will in ten
# years, whatever Sanctum does next. The ONLINE v3 controls deliberately assert
# nothing about the live threshold or member count — they use impossible
# expectations that must fail no matter what the real values are — so this
# self-test does not start reporting itself broken merely because Sanctum
# reconfigured its multisig.
V3_MULTISIG = "AApfiPZgV5MoPU691GwhdDhq5sKEMMH1Uh8S4Z9xvP6b"
V3_AUTHORITY = "47SND7bGKvNXrqfP1bjsLCbwTgZhFBzAgmZ42QSkRScz"
V3_AUTHORITY_INDEX = 1
V3_AUTHORITY_BUMP = 255
V3_CREATE_KEY = "CLniPncNVFynHfyfAQLpizZhrqVpQEs8UuJQ9db4epAF"

# A program that program-control assertions should confirm is under V3_AUTHORITY.
V3_CONTROLLED_PROGRAM = "SP12tWFxD9oJsVWNavTTBZvMbA6gkAmxtVgxdqvyvhY"

# A program with NO upgrade authority at all. Claiming a multisig controls it
# must fail — "immutable" is not "controlled by you", however safe it sounds.
IMMUTABLE_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"


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

    # -- Control 1: offline. Address encoding must round-trip. --------------
    try:
        round_tripped = lib.b58encode(lib.b58decode(KNOWN_MULTISIG))
        record("base58 encode/decode round-trips",
               round_tripped == KNOWN_MULTISIG,
               f"{KNOWN_MULTISIG} -> bytes -> {round_tripped}")
    except lib.CheckerError as exc:
        record("base58 encode/decode round-trips", False, str(exc))

    # -- Control 2: offline. The vault derivation must reproduce a known
    #    published address exactly. This is pure arithmetic: it needs no
    #    network, so it still runs when the chain is unreachable. ----------
    try:
        derived, bump = derive_vault(KNOWN_MULTISIG, 0)
        record("vault PDA derivation matches a known published vault",
               derived == KNOWN_VAULT and bump == KNOWN_VAULT_BUMP,
               f"derived {derived} (bump {bump}), expected {KNOWN_VAULT} "
               f"(bump {KNOWN_VAULT_BUMP})")
    except lib.CheckerError as exc:
        record("vault PDA derivation matches a known published vault", False, str(exc))

    # -- Control 3: offline. Rejecting a malformed address. -----------------
    bad_address = "not-a-real-address-0OIl"
    try:
        lib.parse_pubkey(bad_address)
        record("a malformed address is rejected", False,
               "parse_pubkey accepted rubbish — it should have raised")
    except lib.CheckerError:
        record("a malformed address is rejected", True,
               f"{bad_address!r} raised CheckerError, as it should")

    # -- Control 4: online, POSITIVE. Known-good input must pass. -----------
    try:
        checks, _ = check(KNOWN_MULTISIG, expect_threshold=KNOWN_THRESHOLD,
                          expect_members=KNOWN_MEMBERS, url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-GOOD: correct expectations produce exit 0",
               code == 0, f"exit code {code} (wanted 0)")
    except lib.CheckerError as exc:
        record("KNOWN-GOOD: correct expectations produce exit 0", False, str(exc),
               blocked=True)

    # -- Control 5: online, NEGATIVE. Wrong threshold MUST fail. ------------
    #    This is the control that matters most. If a deliberately wrong claim
    #    still passes, every pass this checker has ever printed is meaningless.
    try:
        checks, _ = check(KNOWN_MULTISIG, expect_threshold=KNOWN_THRESHOLD + 1,
                          url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: a false threshold claim produces exit 1",
               code == 1, f"exit code {code} (wanted 1 — a wrong claim must fail)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a false threshold claim produces exit 1", False, str(exc),
               blocked=True)

    # -- Control 6: online, NEGATIVE. Wrong member count MUST fail. --------
    try:
        checks, _ = check(KNOWN_MULTISIG, expect_members=KNOWN_MEMBERS + 2,
                          url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: a false member count produces exit 1",
               code == 1, f"exit code {code} (wanted 1)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a false member count produces exit 1", False, str(exc),
               blocked=True)

    # -- Control 7: online, NEGATIVE. A non-multisig account must be refused,
    #    not decoded into a confident wrong answer. -------------------------
    try:
        check(NOT_A_MULTISIG, url=url, quiet=True)
        record("KNOWN-BAD: a non-multisig account is refused", False,
               "the checker decoded a non-Squads account instead of refusing")
    except lib.CheckerError as exc:
        # This is the correct outcome: it raised, which the CLI turns into
        # exit 2 ("could not check"), not exit 0 ("all fine").
        record("KNOWN-BAD: a non-multisig account is refused", True,
               f"refused with: {str(exc)[:90]}")

    # -- Control 8: offline. The v3 authority PDA derivation must reproduce a
    #    known address exactly. Pure arithmetic, so it runs with no network.
    try:
        derived, bump = derive_authority_v3(V3_MULTISIG, V3_AUTHORITY_INDEX)
        record("v3 authority PDA derivation matches a known address",
               derived == V3_AUTHORITY and bump == V3_AUTHORITY_BUMP,
               f"derived {derived} (bump {bump}), expected {V3_AUTHORITY} "
               f"(bump {V3_AUTHORITY_BUMP})")
    except lib.CheckerError as exc:
        record("v3 authority PDA derivation matches a known address", False, str(exc))

    # -- Control 9: offline. A v3 multisig address must re-derive from the
    #    create_key stored inside the account.
    try:
        derived, _ = derive_multisig_v3(V3_CREATE_KEY)
        record("v3 multisig PDA re-derives from its create_key",
               derived == V3_MULTISIG,
               f"create_key {V3_CREATE_KEY} -> {derived}, expected {V3_MULTISIG}")
    except lib.CheckerError as exc:
        record("v3 multisig PDA re-derives from its create_key", False, str(exc))

    # -- Control 10: offline, NEGATIVE. The authority index is load-bearing.
    #    Index 2 must NOT produce the index-1 address. If it did, the index
    #    would be decorative and every "this vault" claim would be unfalsifiable.
    try:
        other, _ = derive_authority_v3(V3_MULTISIG, V3_AUTHORITY_INDEX + 1)
        record("KNOWN-BAD: a different authority index yields a different PDA",
               other != V3_AUTHORITY,
               f"index {V3_AUTHORITY_INDEX + 1} -> {other}, which differs from "
               f"index {V3_AUTHORITY_INDEX} -> {V3_AUTHORITY}")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a different authority index yields a different PDA",
               False, str(exc))

    # -- Control 11: offline, NEGATIVE. The v4 seed scheme applied to a v3
    #    multisig must NOT produce the v3 authority. This is the control that
    #    would have caught "just try v4's derive_vault and see if it matches".
    try:
        v4_style, _ = derive_vault(V3_MULTISIG, 0)
        record("KNOWN-BAD: v4 vault seeds do not reproduce a v3 authority PDA",
               v4_style != V3_AUTHORITY,
               f"v4-style derivation gives {v4_style}, not {V3_AUTHORITY}")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: v4 vault seeds do not reproduce a v3 authority PDA",
               False, str(exc))

    # -- Control 12: online, POSITIVE. A live v3 multisig must decode and pass
    #    its structural assertions. Asserts nothing that can rot.
    try:
        checks, facts = check(V3_MULTISIG, url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-GOOD: a live Squads v3 multisig decodes and passes",
               code == 0 and facts["squadsVersion"] == "v3",
               f"exit code {code} (wanted 0), detected version "
               f"{facts['squadsVersion']} (wanted v3)")
    except lib.CheckerError as exc:
        record("KNOWN-GOOD: a live Squads v3 multisig decodes and passes",
               False, str(exc), blocked=True)

    # -- Control 13: online, NEGATIVE. An impossible threshold must fail,
    #    whatever the real one is.
    try:
        checks, _ = check(V3_MULTISIG, expect_threshold=9999, url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: an impossible v3 threshold claim produces exit 1",
               code == 1, f"exit code {code} (wanted 1)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: an impossible v3 threshold claim produces exit 1",
               False, str(exc), blocked=True)

    # -- Control 14: online, POSITIVE. The program-control link must hold for
    #    a program known to be under this multisig.
    try:
        checks, _ = check(V3_MULTISIG,
                          expect_controls_programs=[V3_CONTROLLED_PROGRAM],
                          url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-GOOD: a program really under this multisig passes",
               code == 0, f"exit code {code} (wanted 0)")
    except lib.CheckerError as exc:
        record("KNOWN-GOOD: a program really under this multisig passes",
               False, str(exc), blocked=True)

    # -- Control 15: online, NEGATIVE. The SAME program claimed for a DIFFERENT
    #    multisig must fail. Without this, --expect-controls-program could be
    #    passing for everyone and nobody would notice.
    try:
        checks, _ = check(KNOWN_MULTISIG,
                          expect_controls_programs=[V3_CONTROLLED_PROGRAM],
                          url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: claiming that program for the wrong multisig fails",
               code == 1, f"exit code {code} (wanted 1)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: claiming that program for the wrong multisig fails",
               False, str(exc), blocked=True)

    # -- Control 16: online, NEGATIVE. An immutable program is not "controlled".
    try:
        checks, _ = check(V3_MULTISIG,
                          expect_controls_programs=[IMMUTABLE_PROGRAM],
                          url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: an immutable program is not reported as controlled",
               code == 1, f"exit code {code} (wanted 1)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: an immutable program is not reported as controlled",
               False, str(exc), blocked=True)

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
    negative = len([r for r in results if r["name"].startswith("KNOWN-BAD")
                    or "rejected" in r["name"]])
    print(f"SELF-TEST PASSED: {len(results)} controls, including {negative} negative")
    print("controls that had to fail and did.")
    return 0


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check the threshold, members, vault and authority of a "
                    "Squads v4 multisig on Solana.",
        epilog="Exit 0 = all assertions held, 1 = an assertion is false, "
               "2 = could not check.",
    )
    parser.add_argument("address", nargs="?",
                        help="the multisig account address (base58)")
    parser.add_argument("--expect-threshold", type=int, metavar="N",
                        help="assert the threshold is N")
    parser.add_argument("--expect-members", type=int, metavar="N",
                        help="assert there are exactly N members")
    parser.add_argument("--vault-index", type=int, default=None, metavar="N",
                        help="which vault/authority PDA to derive (default: 0 "
                             "for Squads v4, 1 for Squads v3, each being that "
                             "version's first vault)")
    parser.add_argument("--expect-controls-program", metavar="PROGRAM_ID",
                        action="append", dest="expect_controls_programs",
                        help="assert this program's on-chain upgrade authority "
                             "is this multisig's signer PDA. Repeatable.")
    parser.add_argument("--find-multisig", metavar="AUTHORITY",
                        help="search mode: given a signing PDA, find the multisig "
                             "it belongs to by enumerating every Squads multisig "
                             "and re-deriving. Slow; needs getProgramAccounts.")
    parser.add_argument("--find-version", choices=["v3", "v4"], default="v3",
                        help="which Squads version --find-multisig searches "
                             "(default v3)")
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

    if args.find_multisig:
        print(f"Searching Squads {args.find_version} for the multisig whose signing "
              f"PDA is\n  {args.find_multisig}")
        print("This enumerates every multisig and re-derives each one. Slow by "
              "design.\n")

        def progress(index, position, total):
            print(f"  ...authority index {index}: {position}/{total}")

        try:
            hit = find_multisig_for_authority(
                args.find_multisig, version=args.find_version,
                url=args.rpc, progress=progress)
        except lib.CheckerError as exc:
            print(f"\nCOULD NOT CHECK: {exc}")
            return 2
        if not hit:
            print("\nNo multisig found. That is a real answer: this address is "
                  "not a\nSquads " + args.find_version + " signing PDA at any of "
                  "the indices searched.")
            return 1
        print(f"\nFOUND: multisig {hit['multisig']}")
        print(f"  Squads {hit['version']}, authority/vault index {hit['index']}, "
              f"bump {hit['bump']}")
        print(f"  searched {hit['searched']} accounts")
        print("\nVerify this in the forward direction (fast, no search):")
        print(f"  python3 checkers/multisig.py {hit['multisig']} \\")
        print(f"      --vault-index {hit['index']}")
        return 0

    if not args.address:
        parser.print_help()
        print("\nNo address given. Try --self-test to confirm this checker works.")
        return 2

    try:
        checks, facts = check(
            args.address,
            expect_threshold=args.expect_threshold,
            expect_members=args.expect_members,
            vault_index=args.vault_index,
            expect_controls_programs=args.expect_controls_programs,
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
