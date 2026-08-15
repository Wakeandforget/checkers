#!/usr/bin/env python3
"""
multisig.py — check who really controls a multisig wallet on Solana.

CLAIM CLASS: "the treasury is in a N-of-M multisig" — thresholds, member
lists, member permissions, the vault address, the config authority and the
time lock of a multisig on Solana mainnet. Three programs are decoded:
Squads v4, the older Squads v3 (squads-mpl), and the Anchor/Serum example
multisig (coral-xyz/multisig) that many 2021-2022 protocols still run on.
The family is detected from the account's owner, never guessed.

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
  * the multisig program itself      (if the multisig PROGRAM is upgradeable,
                                      whoever holds that authority can deploy new
                                      logic that signs for the same PDA. Every
                                      run reports this, either way.)

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

# The Anchor/Serum example multisig ("serum-multisig", now coral-xyz/multisig).
# Not a Squads product at all — a separate, much simpler program that a great
# many 2021-2022 Solana protocols adopted because it was the reference
# implementation in Anchor's own repository. It still holds program upgrade
# authority for live protocols. Two properties make it worth decoding here:
# there are no per-member permissions and no config authority, and the deployed
# program is itself immutable (checked at run time below, not assumed).
SERUM_MULTISIG_PROGRAM = "msigmtwzgXJHj2ext4XJjCDmpbcMuufFb5cHuwg6Xdt"

# Which owner means which layout. Nothing is inferred from the address itself.
SQUADS_PROGRAMS = {
    SQUADS_PROGRAM: "v4",
    SQUADS_V3_PROGRAM: "v3",
    SERUM_MULTISIG_PROGRAM: "serum",
}

# Human names for the families, for output and error messages.
FAMILY_NAMES = {
    "v4": "Squads v4",
    "v3": "Squads v3 (squads-mpl)",
    "serum": "Anchor/Serum multisig (coral-xyz/multisig)",
}

# A member's permissions are a bitmask: one bit per power.
#   1 Initiate — may propose a transaction
#   2 Vote     — may approve or reject one
#   4 Execute  — may push an already-approved transaction through
# A member with Vote but not Execute still counts toward the threshold.
PERMISSION_BITS = [(1, "Initiate"), (2, "Vote"), (4, "Execute")]

# The genesis hash of Solana mainnet-beta. Checked before anything is read, so
# that a devnet or forked endpoint cannot quietly supply different bytes for the
# same addresses.
MAINNET_GENESIS = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"


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


def decode_multisig_serum(data: bytes) -> dict:
    """Decode an Anchor/Serum `Multisig` account from its raw bytes.

    Layout, from the published program source —
    https://github.com/coral-xyz/multisig, `programs/multisig/src/lib.rs`,
    `pub struct Multisig` — read in this exact order with no padding:

        vec<[32]> owners           4-byte count, then that many 32-byte keys
        u64  threshold             signatures needed to execute
        u8   nonce                 the bump this multisig's signer PDA uses
        u32  owner_set_seqno       bumped every time the owner set changes;
                                   any transaction proposed under an older
                                   sequence number can no longer be approved
                                   or executed

    Note the owners vector comes FIRST here, before the threshold — the reverse
    of both Squads layouts. Reading the Squads order into these bytes would
    yield a plausible-looking threshold made of the first four bytes of
    somebody's public key, which is exactly the sort of confident nonsense the
    discriminator check above exists to prevent.

    Two structural differences from Squads, both in the reader's favour and
    neither of them an omission:

      * No per-member permission mask. Every owner may propose, approve and
        execute, so the whole owner list counts toward the threshold.
      * No config authority. `set_owners`, `change_threshold` and
        `set_owners_and_change_threshold` all take the `Auth` account context,
        which requires the multisig's own signer PDA as a `Signer`. That PDA
        can only be produced by `execute_transaction`, which refuses unless
        `threshold` owners have already approved. So the membership and the
        threshold can only be changed by the multisig voting to change them.
        There is no back door of the kind Squads v4's config authority is.
    """
    cursor = lib.Cursor(data, label="Multisig(serum)")
    cursor.expect_discriminator("Multisig")

    owner_count = cursor.u32()
    if owner_count > 10_000:
        raise lib.CheckerError(
            f"owner count reads as {owner_count}, which is absurd. The layout "
            "assumed here does not match this account."
        )
    members = [
        {"key": cursor.pubkey(), "mask": None,
         "permissions": ["Initiate", "Vote", "Execute"]}
        for _ in range(owner_count)
    ]

    decoded = {
        "members": members,
        "threshold": cursor.u64(),
        "nonce": cursor.u8(),
        "ownerSetSeqno": cursor.u32(),
    }
    decoded["configAuthority"] = None       # cannot exist in this program
    decoded["timeLock"] = None              # not a feature of this program
    # This program never stores a transaction counter on the multisig; each
    # proposal is its own account. Reporting 0 would be a lie, so say nothing.
    decoded["transactionIndex"] = None
    decoded["createKey"] = None
    # The account is allocated with room to grow the owner list, so leftover
    # bytes are expected here and are NOT evidence of a wrong layout — unlike
    # in Squads v3, where the account is sized exactly.
    decoded["trailingBytes"] = cursor.remaining
    return decoded


def decode_transaction_serum(data: bytes) -> dict:
    """Decode an Anchor/Serum `Transaction` account — one proposal.

    Same source file as the Multisig struct, `pub struct Transaction`:

        [32]  multisig            which multisig this proposal belongs to
        [32]  program_id          the program it would call
        vec<TransactionAccount>   34 bytes each: 32-byte key, is_signer, is_writable
        vec<u8>   data            the raw instruction data it would pass
        vec<bool> signers         signers[i] is true iff owners[i] approved
        bool  did_execute         set once, so a proposal cannot run twice
        u32   owner_set_seqno     the owner set this was proposed under

    Why this is worth decoding rather than trusting a threshold field alone: the
    Multisig account says how many approvals a proposal *would* need today. This
    account says how many a specific past action actually *got*, and it survives
    on chain after execution. That turns "6 of 13 must sign" from a rule into a
    receipt.

    Note that `signers` is one bool per owner *at the time of proposal*, so its
    length is the member count that applied then, which is not necessarily the
    member count now. The two are reported separately for exactly that reason.
    """
    cursor = lib.Cursor(data, label="Transaction(serum)")
    cursor.expect_discriminator("Transaction")

    decoded = {
        "multisig": cursor.pubkey(),
        "programId": cursor.pubkey(),
    }

    account_count = cursor.u32()
    if account_count > 10_000:
        raise lib.CheckerError(
            f"account count reads as {account_count}, which is absurd. The "
            "layout assumed here does not match this account."
        )
    decoded["accounts"] = [
        {"pubkey": cursor.pubkey(),
         "isSigner": bool(cursor.u8()),
         "isWritable": bool(cursor.u8())}
        for _ in range(account_count)
    ]

    data_len = cursor.u32()
    decoded["data"] = cursor.take(data_len).hex()

    signer_count = cursor.u32()
    if signer_count > 10_000:
        raise lib.CheckerError(
            f"signer-flag count reads as {signer_count}, which is absurd. The "
            "layout assumed here does not match this account."
        )
    flags = [bool(cursor.u8()) for _ in range(signer_count)]
    decoded["signers"] = flags
    decoded["approvals"] = sum(flags)
    decoded["ownerSlots"] = signer_count
    decoded["didExecute"] = bool(cursor.u8())
    decoded["ownerSetSeqno"] = cursor.u32()
    decoded["trailingBytes"] = cursor.remaining
    return decoded


def derive_signer_serum(multisig_address: str, nonce: int):
    """Re-derive the Anchor/Serum multisig's signing PDA, using its own nonce.

    From `execute_transaction` in the program source:

        let seeds = &[multisig_key.as_ref(), &[ctx.accounts.multisig.nonce]];

    One seed — the multisig's own address — and the bump is the `nonce` field
    stored in the account, not necessarily the canonical bump that
    find_program_address would return. Deriving with the canonical bump would
    be right almost always and silently wrong the rest of the time, so the
    stored nonce is used and the caller is told whether it is canonical.

    Returns (address, nonce_used, is_canonical).
    """
    if not 0 <= nonce <= 255:
        raise lib.CheckerError("nonce must be a single byte")
    program = lib.parse_pubkey(SERUM_MULTISIG_PROGRAM)
    seed = lib.parse_pubkey(multisig_address)
    raw = lib.create_program_address([seed, bytes([nonce])], program)
    canonical, canonical_bump = lib.find_program_address([seed], program)
    return lib.b58encode(raw), nonce, (raw == canonical and nonce == canonical_bump)


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
          expect_controls_programs=None, proposals=None, url=None, quiet=False):
    """Run the whole check. Returns (Checks, facts-dict).

    Raises CheckerError if it could not get far enough to assert anything —
    the caller turns that into exit code 2, never into a pass.
    """
    out = sys.stderr if quiet else sys.stdout
    checks = lib.Checks()

    if not quiet:
        lib.banner(f"MULTISIG CHECK — {address}", url=url, stream=out)

    # --- 0. confirm which chain we are even looking at ----------------------
    # Every address below is meaningful only on mainnet-beta. The same address
    # on devnet, or on a forked endpoint, holds different bytes — and a wrong
    # answer that looks right is the worst outcome this script can produce.
    # This is exit 2 territory, not exit 1: reading the wrong chain does not
    # make anybody's claim false, it makes this run worthless.
    genesis = lib.rpc("getGenesisHash", [], url=url)
    if genesis != MAINNET_GENESIS:
        raise lib.CheckerError(
            f"this endpoint reports genesis hash {genesis}, which is not "
            f"Solana mainnet-beta ({MAINNET_GENESIS}). Refusing to report "
            "mainnet addresses from some other chain."
        )
    checks.expect("the endpoint really is Solana mainnet-beta (genesis hash)",
                  genesis, MAINNET_GENESIS)

    # --- 1. fetch and confirm what kind of account this is ------------------
    account = lib.get_account(address, url=url)

    # If this is not owned by a multisig program this script understands, then
    # its bytes mean nothing here, whatever anyone calls the account. Assert
    # rather than assume.
    version = SQUADS_PROGRAMS.get(account["owner"])
    checks.expect_true(
        "the account is owned by a multisig program this checker can decode "
        "(Squads v4, Squads v3, or the Anchor/Serum multisig)",
        version is not None,
        f"owner is {account['owner']}"
        + (f" — {FAMILY_NAMES[version]}" if version else " — not a known multisig program"),
    )
    if version is None:
        # Decoding foreign bytes with a known layout would produce garbage that
        # looks like data. Stop here and say why.
        known = ", ".join(f"{FAMILY_NAMES[v]} ({p})" for p, v in SQUADS_PROGRAMS.items())
        raise lib.CheckerError(
            f"{address} is owned by {account['owner']}, which is none of the "
            f"multisig programs this script can decode: {known}."
        )

    serum_canonical_nonce = None
    if version == "v4":
        multisig = decode_multisig(account["data"])
        # v4 vaults are indexed from 0.
        signer_index = 0 if vault_index is None else vault_index
    elif version == "v3":
        multisig = decode_multisig_v3(account["data"])
        # v3's default vault is authority index 1, not 0. Defaulting to 0 here
        # would derive a real-looking address that holds nothing.
        signer_index = 1 if vault_index is None else vault_index
    else:
        multisig = decode_multisig_serum(account["data"])
        # This program has exactly one signing PDA per multisig — there is no
        # index at all. Silently ignoring a --vault-index would let a reader
        # think they had checked a vault that does not exist.
        if vault_index not in (None, 0):
            raise lib.CheckerError(
                "the Anchor/Serum multisig has exactly one signer PDA per "
                f"multisig, so --vault-index {vault_index} has no meaning here"
            )
        signer_index = 0

    # --- 2. report the facts -----------------------------------------------
    if version == "serum":
        vault_address, vault_bump, serum_canonical_nonce = derive_signer_serum(
            address, multisig["nonce"])
    else:
        vault_address, vault_bump = derive_signer(address, version, signer_index)
    config_authority = multisig["configAuthority"]
    # In v3 the field cannot exist; in v4, "unset" is written as the system program.
    authority_is_none = (config_authority is None
                         or config_authority == lib.SYSTEM_PROGRAM)

    # Who, if anyone, can replace the multisig program's own code. If that
    # authority is set, every guarantee below is only as good as whoever holds
    # it: they can deploy a new program that signs for the same PDA. Almost
    # nobody checks this, and it is one account lookup.
    try:
        program_control = spl_mint.program_upgrade_authority(account["owner"], url=url)
        program_authority = program_control.get("upgradeAuthority")
    except lib.CheckerError as exc:
        program_control = {"error": str(exc)}
        program_authority = "unknown"

    if not quiet:
        print(f"  multisig family    {FAMILY_NAMES[version]}", file=out)
        print(f"  threshold          {multisig['threshold']} of {len(multisig['members'])}",
              file=out)
        print(f"  members            {len(multisig['members'])}", file=out)
        if multisig["timeLock"] is None:
            print(f"  time lock          n/a — {FAMILY_NAMES[version]} has no "
                  "time lock feature", file=out)
        else:
            print(f"  time lock          {describe_timelock(multisig['timeLock'])}",
                  file=out)
        if config_authority is None:
            print(f"  config authority   n/a — {FAMILY_NAMES[version]} has no "
                  "config-authority field, so\n                     members and "
                  "threshold can only change through a multisig transaction",
                  file=out)
        else:
            print(f"  config authority   "
                  f"{'none — members and threshold can only change by a vote' if authority_is_none else config_authority}",
                  file=out)
        if config_authority is not None and not authority_is_none:
            print("                     ^ THIS ACCOUNT CAN CHANGE THE MEMBERS AND THE",
                  file=out)
            print("                       THRESHOLD WITHOUT A VOTE.", file=out)
        if version == "serum":
            print(f"  signer PDA         {vault_address}  (nonce {vault_bump}"
                  f"{'' if serum_canonical_nonce else ', NOT the canonical bump'})",
                  file=out)
            print(f"                     re-derived here, not read from an explorer",
                  file=out)
            print(f"  owner_set_seqno    {multisig['ownerSetSeqno']} — the owner "
                  "list has been changed this\n                     many times "
                  "since the multisig was created", file=out)
        else:
            label = "vault" if version == "v4" else "authority"
            print(f"  {label} (index {signer_index})  {vault_address}  (bump {vault_bump})",
                  file=out)
            print(f"                     re-derived here, not read from an explorer",
                  file=out)
        if multisig["transactionIndex"] is not None:
            print(f"  transactions       {multisig['transactionIndex']} proposed to date",
                  file=out)
        print(f"  multisig program   {account['owner']}", file=out)
        if program_authority is None:
            print("                     IMMUTABLE — nobody can replace this "
                  "program's code", file=out)
        else:
            print(f"                     *** UPGRADEABLE BY {program_authority} — "
                  "that account can\n                     replace the multisig "
                  "logic itself ***", file=out)
        print(f"  account            {account['lamports']} lamports of rent, "
              f"{len(account['data'])} bytes", file=out)
        print("", file=out)
        print("  MEMBERS", file=out)
        for member in multisig["members"]:
            if member["mask"] is None:
                print(f"    {member['key']}  (every member may propose, "
                      f"vote and execute)", file=out)
            else:
                print(f"    {member['key']}  mask={member['mask']} "
                      f"{'+'.join(member['permissions']) or 'NO PERMISSIONS'}", file=out)

    checks.observe("multisig family", FAMILY_NAMES[version])
    checks.observe("threshold", multisig["threshold"])
    checks.observe("member count", len(multisig["members"]))
    checks.observe("signer PDA (derived)", vault_address)
    checks.observe("config authority",
                   f"n/a ({FAMILY_NAMES[version]} has no such field)"
                   if config_authority is None else config_authority)
    checks.observe("time lock (seconds)",
                   f"n/a ({FAMILY_NAMES[version]} has no time lock)"
                   if multisig["timeLock"] is None else multisig["timeLock"])
    if version == "serum":
        checks.observe("owner_set_seqno (times the owner list has changed)",
                       multisig["ownerSetSeqno"])
    # An observation, not an assertion, for the same reason a threshold of 1 is:
    # an upgradeable multisig program is a true fact about the arrangement, not
    # a false claim by anyone. But it is the fact that decides how much the rest
    # of this output is worth, so it is stated either way.
    checks.observe(
        "the multisig program's own upgrade authority — whoever holds it can "
        "replace the multisig logic and sign for the same PDA",
        "none — the program is immutable" if program_authority is None
        else str(program_authority))

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

    if version == "serum":
        # The signer PDA above was derived with the nonce stored in the account,
        # because that is the bump the program signs with. Whether that is also
        # the canonical bump is a separate question, and the answer belongs in
        # the output rather than in an assumption. Every honest deployment uses
        # the canonical one; a non-canonical nonce is not proof of anything bad,
        # but a reader comparing this address against find_program_address by
        # hand would otherwise get a different answer and not know why.
        checks.expect_true(
            "the signer PDA derives from the multisig's own address with the "
            "nonce stored in the account, and that nonce is the canonical bump",
            bool(serum_canonical_nonce),
            f"nonce {multisig['nonce']}"
            + ("" if serum_canonical_nonce
               else " — NOT canonical; find_program_address returns a different "
                    "address, and only this one can sign"),
        )
        # Sized with room to grow the owner list, so leftover bytes are normal
        # here and prove nothing either way. Reported, not asserted.
        checks.observe("bytes left unused after the owner list",
                       multisig["trailingBytes"])

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

    # --- 6. "and here is a proposal it actually executed" -------------------
    # The threshold above is a rule about the future. A proposal account is a
    # receipt from the past, and it stays on chain after execution. Checking one
    # is how "6 of 13 must sign" stops being a promise and becomes a record.
    decoded_proposals = []
    for proposal_address in (proposals or []):
        if version != "serum":
            raise lib.CheckerError(
                "--proposal decodes the Anchor/Serum multisig's Transaction "
                f"accounts; this multisig is {FAMILY_NAMES[version]}"
            )
        proposal_account = lib.get_account(proposal_address, url=url)
        if proposal_account["owner"] != account["owner"]:
            raise lib.CheckerError(
                f"{proposal_address} is owned by {proposal_account['owner']}, "
                f"not by {account['owner']} — it is not a proposal of this "
                "multisig's program"
            )
        proposal = decode_transaction_serum(proposal_account["data"])
        proposal["address"] = proposal_address
        decoded_proposals.append(proposal)

        checks.expect(
            f"proposal {proposal_address} belongs to this multisig",
            proposal["multisig"], address)
        # Only meaningful for one that ran: an unexecuted proposal is allowed
        # to be short of approvals, that is what "pending" means.
        if proposal["didExecute"]:
            checks.expect_true(
                f"proposal {proposal_address} was executed with at least "
                f"`threshold` approvals recorded on chain",
                proposal["approvals"] >= multisig["threshold"],
                f"{proposal['approvals']} of {proposal['ownerSlots']} owner "
                f"slots approved; threshold is {multisig['threshold']}",
            )
        checks.observe(f"proposal {proposal_address}: approvals recorded",
                       f"{proposal['approvals']} of {proposal['ownerSlots']}")
        checks.observe(f"proposal {proposal_address}: executed",
                       proposal["didExecute"])
        # A proposal made under an older owner set can no longer be approved or
        # executed — the program compares these two numbers and refuses. Worth
        # showing rather than leaving the reader to wonder.
        checks.observe(
            f"proposal {proposal_address}: owner_set_seqno",
            f"{proposal['ownerSetSeqno']} (multisig is now at "
            f"{multisig['ownerSetSeqno']}"
            + ("" if proposal["ownerSetSeqno"] == multisig["ownerSetSeqno"]
               else "; this proposal is void and can never execute") + ")")

    if decoded_proposals and not quiet:
        print("", file=out)
        print("  PROPOSALS DECODED", file=out)
        for proposal in decoded_proposals:
            print(f"    {proposal['address']}", file=out)
            print(f"      calls        {proposal['programId']}", file=out)
            print(f"      ix data      0x{proposal['data'] or '(empty)'}", file=out)
            print(f"      approvals    {proposal['approvals']} of "
                  f"{proposal['ownerSlots']} owner slots  "
                  f"(threshold {multisig['threshold']})", file=out)
            print(f"      executed     {proposal['didExecute']}", file=out)
            print(f"      seqno        {proposal['ownerSetSeqno']}", file=out)
            print(f"      who approved (index into the owner list at the time):",
                  file=out)
            for index, did in enumerate(proposal["signers"]):
                if did:
                    key = (multisig["members"][index]["key"]
                           if index < len(multisig["members"]) else "(owner list has changed)")
                    print(f"        [{index:>2}] {key}", file=out)

    facts = {
        "checkedAt": lib.utc_now(),
        "rpc": lib.mask_url(url or lib.rpc_url()),
        "multisigAddress": address,
        "proposals": decoded_proposals,
        "squadsVersion": version,
        "multisigFamily": FAMILY_NAMES[version],
        "squadsProgram": account["owner"],
        "owner": account["owner"],
        "multisigProgramUpgradeAuthority": program_authority,
        "multisigProgramControl": program_control,
        "vault": {"index": signer_index, "address": vault_address,
                  "bump": vault_bump,
                  "canonicalBump": None if version != "serum"
                                   else bool(serum_canonical_nonce)},
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

# A real Anchor/Serum multisig: the one holding the upgrade authority of
# Marinade's liquid staking program, identified in wake 6 by reading the
# program's own last upgrade transaction
# (wyCLBNG716ScBE1rAU7FC2EmqHJxcho3LCofb2vLBcCDxVfXn6SF8b3gfjda1cUEhdYeKwbF2j4AmhimxNA9PUh)
# rather than by guessing.
#
# As with the v3 constants: the OFFLINE controls are PDA arithmetic and cannot
# rot. The ONLINE controls assert only that the account decodes and that
# impossible claims fail — never a live threshold or member count — so Marinade
# reconfiguring its multisig will not make this self-test report itself broken.
SERUM_MULTISIG = "magrsHFQxkkioAy45VWnZnFBBdKVdy2ZiRoRGYT9Wed"
SERUM_SIGNER = "551FBXSXdhcRDDkdcb3ThDRg84Mwe5Zs6YjJ1EEoyzBp"
SERUM_NONCE = 253
SERUM_CONTROLLED_PROGRAM = "MarBmsSgKXdrN1egZf5sqe1TMai9K1rChYNDJgjq7aD"

# The proposal account that performed that program's most recent upgrade. It
# has already executed, and an executed proposal is never written again, so
# these two numbers are as fixed as a confirmed transaction is.
SERUM_EXECUTED_PROPOSAL = "C2kiVNvbGaXE31M9fqMdaSEH8sUPMAB78pNwsYWP8L1m"
SERUM_PROPOSAL_APPROVALS = 6


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

    # -- Control 17: offline. The Anchor/Serum signer PDA must reproduce a
    #    known address exactly, derived with the account's stored nonce.
    try:
        derived, nonce, canonical = derive_signer_serum(SERUM_MULTISIG, SERUM_NONCE)
        record("serum signer PDA derivation matches a known address",
               derived == SERUM_SIGNER,
               f"derived {derived} (nonce {nonce}, canonical={canonical}), "
               f"expected {SERUM_SIGNER}")
    except lib.CheckerError as exc:
        record("serum signer PDA derivation matches a known address", False, str(exc))

    # -- Control 18: offline, NEGATIVE. The nonce is load-bearing. A different
    #    nonce must give a different address, or "this is the signer" would be
    #    unfalsifiable.
    try:
        wrong_nonce = SERUM_NONCE - 1
        other = None
        while wrong_nonce >= 0 and other is None:
            try:
                other, _, _ = derive_signer_serum(SERUM_MULTISIG, wrong_nonce)
            except lib.CheckerError:
                wrong_nonce -= 1     # that bump lands on the curve; try the next
        record("KNOWN-BAD: a different nonce yields a different serum signer PDA",
               other is not None and other != SERUM_SIGNER,
               f"nonce {wrong_nonce} -> {other}, which differs from nonce "
               f"{SERUM_NONCE} -> {SERUM_SIGNER}")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a different nonce yields a different serum signer PDA",
               False, str(exc))

    # -- Control 19: offline, NEGATIVE. The Squads seed schemes applied to a
    #    serum multisig must NOT produce its signer. Three families now share
    #    one code path; this is what stops them being silently interchangeable.
    try:
        v4_style, _ = derive_vault(SERUM_MULTISIG, 0)
        v3_style, _ = derive_authority_v3(SERUM_MULTISIG, 1)
        record("KNOWN-BAD: Squads seed schemes do not reproduce a serum signer",
               v4_style != SERUM_SIGNER and v3_style != SERUM_SIGNER,
               f"v4-style gives {v4_style}, v3-style gives {v3_style}, "
               f"neither is {SERUM_SIGNER}")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: Squads seed schemes do not reproduce a serum signer",
               False, str(exc))

    # -- Control 20: offline, NEGATIVE. The owners vector comes first in this
    #    layout and last in Squads v3. Feeding v3 bytes to the serum decoder
    #    must raise rather than invent a threshold out of somebody's pubkey.
    try:
        fake = (lib.anchor_discriminator("Multisig")
                + (3).to_bytes(4, "little") + bytes(32) * 2)   # says 3 owners, has 2
        try:
            decode_multisig_serum(fake)
            record("KNOWN-BAD: truncated serum bytes are refused, not guessed at",
                   False, "the decoder returned a result from short data")
        except lib.CheckerError as exc:
            record("KNOWN-BAD: truncated serum bytes are refused, not guessed at",
                   True, f"refused with: {str(exc)[:90]}")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: truncated serum bytes are refused, not guessed at",
               False, str(exc))

    # -- Control 21: online, POSITIVE. A live serum multisig must decode and
    #    pass its structural assertions. Asserts nothing that can rot.
    try:
        checks, facts = check(SERUM_MULTISIG, url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-GOOD: a live Anchor/Serum multisig decodes and passes",
               code == 0 and facts["squadsVersion"] == "serum",
               f"exit code {code} (wanted 0), detected family "
               f"{facts['squadsVersion']} (wanted serum)")
    except lib.CheckerError as exc:
        record("KNOWN-GOOD: a live Anchor/Serum multisig decodes and passes",
               False, str(exc), blocked=True)

    # -- Control 22: online, NEGATIVE. An impossible threshold must fail,
    #    whatever the real one is.
    try:
        checks, _ = check(SERUM_MULTISIG, expect_threshold=9999, url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: an impossible serum threshold claim produces exit 1",
               code == 1, f"exit code {code} (wanted 1)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: an impossible serum threshold claim produces exit 1",
               False, str(exc), blocked=True)

    # -- Control 23: online, NEGATIVE. An impossible member count must fail.
    try:
        checks, _ = check(SERUM_MULTISIG, expect_members=9999, url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: an impossible serum member count produces exit 1",
               code == 1, f"exit code {code} (wanted 1)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: an impossible serum member count produces exit 1",
               False, str(exc), blocked=True)

    # -- Control 24: online, POSITIVE. The program-control link must hold for
    #    a program known to be under this serum multisig.
    try:
        checks, _ = check(SERUM_MULTISIG,
                          expect_controls_programs=[SERUM_CONTROLLED_PROGRAM],
                          url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-GOOD: a program really under the serum multisig passes",
               code == 0, f"exit code {code} (wanted 0)")
    except lib.CheckerError as exc:
        record("KNOWN-GOOD: a program really under the serum multisig passes",
               False, str(exc), blocked=True)

    # -- Control 25: online, NEGATIVE. That same program claimed for a
    #    DIFFERENT multisig must fail.
    try:
        checks, _ = check(V3_MULTISIG,
                          expect_controls_programs=[SERUM_CONTROLLED_PROGRAM],
                          url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: that program claimed for the wrong multisig fails",
               code == 1, f"exit code {code} (wanted 1)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: that program claimed for the wrong multisig fails",
               False, str(exc), blocked=True)

    # -- Control 26: offline, NEGATIVE. The proposal decoder must refuse bytes
    #    that are not a Transaction account, rather than reading a pubkey as an
    #    approval count.
    try:
        try:
            decode_transaction_serum(lib.anchor_discriminator("Multisig") + bytes(200))
            record("KNOWN-BAD: non-proposal bytes are refused by the proposal decoder",
                   False, "the decoder accepted a Multisig discriminator")
        except lib.CheckerError as exc:
            record("KNOWN-BAD: non-proposal bytes are refused by the proposal decoder",
                   True, f"refused with: {str(exc)[:90]}")
    except Exception as exc:                     # noqa: BLE001 - controls must not crash the run
        record("KNOWN-BAD: non-proposal bytes are refused by the proposal decoder",
               False, repr(exc))

    # -- Control 27: online, POSITIVE. The pinned proposal — the one that
    #    performed Marinade's most recent program upgrade — must decode, and
    #    the approvals it recorded must meet the threshold. This is pinned to a
    #    proposal account that has already executed, so it cannot change.
    try:
        checks, facts = check(SERUM_MULTISIG, proposals=[SERUM_EXECUTED_PROPOSAL],
                              url=url, quiet=True)
        proposal = facts["proposals"][0]
        code = checks.exit_code()
        record("KNOWN-GOOD: an executed proposal decodes with enough approvals",
               code == 0 and proposal["didExecute"]
               and proposal["approvals"] == SERUM_PROPOSAL_APPROVALS,
               f"exit code {code} (wanted 0), approvals {proposal['approvals']} "
               f"(wanted {SERUM_PROPOSAL_APPROVALS}), executed "
               f"{proposal['didExecute']} (wanted True)")
    except lib.CheckerError as exc:
        record("KNOWN-GOOD: an executed proposal decodes with enough approvals",
               False, str(exc), blocked=True)

    # -- Control 28: online, NEGATIVE. An account that is not a proposal of this
    #    multisig must be refused, not decoded. Passing the multisig's own
    #    address is the cheapest way to try to fool it.
    try:
        check(SERUM_MULTISIG, proposals=[SERUM_MULTISIG], url=url, quiet=True)
        record("KNOWN-BAD: a non-proposal account is refused as a proposal",
               False, "the checker decoded the multisig account as a proposal")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: a non-proposal account is refused as a proposal",
               True, f"refused with: {str(exc)[:90]}")

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
        description="Check the threshold, members, signer PDA and authority of a "
                    "Squads v4, Squads v3 or Anchor/Serum multisig on Solana.",
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
                             "version's first vault; the Anchor/Serum multisig "
                             "has exactly one signer PDA and takes no index)")
    parser.add_argument("--expect-controls-program", metavar="PROGRAM_ID",
                        action="append", dest="expect_controls_programs",
                        help="assert this program's on-chain upgrade authority "
                             "is this multisig's signer PDA. Repeatable.")
    parser.add_argument("--proposal", metavar="ADDRESS",
                        action="append", dest="proposals",
                        help="decode a proposal (Transaction) account of this "
                             "multisig and report how many owners actually "
                             "approved it. Anchor/Serum multisigs only. "
                             "Repeatable.")
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
            proposals=args.proposals,
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
