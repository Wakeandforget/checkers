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
import time
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

# How big a v3 `Ms` account is before its member list. Straight from the
# program's own source — Squads-Protocol/squads-mpl,
# `programs/squads-mpl/src/state.rs`, `impl Ms { pub const SIZE_WITHOUT_MEMBERS }`:
#
#     8 discriminator + 2 threshold + 2 authority_index + 4 transaction_index
#   + 4 ms_change_index + 1 bump + 32 create_key + 1 allow_external_execute
#   + 4 vec length                                                    = 58
#
# So a well-formed account is 58 + 32 * capacity bytes, and capacity is >= the
# number of members, never equal to it by any rule. `add_member` (lib.rs:105-110)
# reallocs "space for 10 more keys" — 320 bytes — whenever the last spare slot
# is taken, and `remove_member` shrinks the vector without shrinking the
# account. Spare slots are therefore the ordinary state of a live v3 multisig.
#
# WAKE 15 CORRECTION. Until this wake the v3 path asserted that ZERO bytes were
# left over, and returned exit 1 — "an assertion is false" — for any v3 multisig
# with room to grow. Sanctum's happened to be sized exactly, so wake 3 passed and
# the bug hid; Streamflow's (F8aHkn9zir2Yx2jQbm3QSvRKuibib1WDPKBmPuoXNP8D, 538
# bytes = 58 + 32x15, five members, ten spare slots) failed in wake 10, and four
# consecutive wakes deferred the fix. It was the worst kind of wrong: a checker
# reporting a false claim where the claim was fine and the checker was not.
MS_SIZE_WITHOUT_MEMBERS = 58

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

    # Spare member slots. A v3 account is NOT sized exactly to its member list:
    # `add_member` grows it ten slots at a time and `remove_member` never
    # shrinks it, so slack is the normal state, not a warning sign. See the
    # note on MS_SIZE_WITHOUT_MEMBERS. What must hold is that the slack is a
    # whole number of 32-byte member slots — a wrong layout would land
    # off-slot with probability 31/32.
    decoded["accountBytes"] = len(data)
    spare = len(data) - MS_SIZE_WITHOUT_MEMBERS - 32 * member_count
    decoded["spareMemberSlots"] = spare // 32 if spare >= 0 else None
    decoded["slotAligned"] = spare >= 0 and spare % 32 == 0
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


# ---------------------------------------------------------------------------
# The other direction: "who can upgrade this program?"
# ---------------------------------------------------------------------------
#
# resolve_program_control() answers "does MY multisig control program X". That
# assumes you already know the controller. The commoner reader question is the
# reverse and has no multisig in it at all: a docs page names an address as the
# upgrade authority, and the reader wants to know (a) whether that is still the
# address on chain and (b) what KIND of thing it is — one keypair somebody
# carries, a multisig vault, a governance program. Those are different risks
# and they are routinely described in the same sentence.

# The BPF Upgradeable Loader's instruction enum, from the loader's own source
# (agave, `sdk/program/src/loader_upgradeable_instruction.rs`). Only the tag —
# a u32 little-endian at offset 0 — is needed to tell these apart.
LOADER_IX_NAMES = {
    0: "InitializeBuffer",
    1: "Write",
    2: "DeployWithMaxDataLen",
    3: "Upgrade",
    4: "SetAuthority",
    5: "Close",
    6: "ExtendProgram",
    7: "SetAuthorityChecked",
}

# Which account index carries the NEW authority, and which carries the signing
# authority, for the instructions that move control. From the same source.
LOADER_IX_AUTHORITY_SLOTS = {
    # tag: (index of current/signing authority, index of new authority or None)
    2: (7, None),    # DeployWithMaxDataLen: [payer, programdata, program, buffer,
                     #                        rent, clock, system, authority]
    3: (6, None),    # Upgrade: [programdata, program, buffer, spill, rent, clock, authority]
    4: (1, 2),       # SetAuthority: [programdata, current authority, new authority?]
    7: (1, 2),       # SetAuthorityChecked: [programdata, current authority, new authority]
}


def classify_authority(address: str, url=None) -> dict:
    """What KIND of account is this upgrade authority?

    The distinction that matters to a reader:

      * on the ed25519 curve  -> a keypair exists for it. One signature is
        enough. Whoever holds that file can replace the program's code.
      * off the curve         -> a program-derived address. No private key can
        exist; only the owning program can sign, so control is whatever that
        program's rules are (a Squads threshold, a governance vote, a timelock).

    An address with no account at all is still a perfectly good signer: a
    keypair that has never been funded holds nothing and appears nowhere until
    it signs. So "no account" is reported, not treated as an error.
    """
    raw = lib.parse_pubkey(address)
    on_curve = lib.is_on_curve(raw)
    try:
        account = lib.get_account(address, url=url)
    except lib.CheckerError:
        account = None

    owner = account["owner"] if account else None
    family = SQUADS_PROGRAMS.get(owner)

    if on_curve:
        kind = ("plain keypair (System-owned account)" if account
                else "plain keypair (no account on chain — never funded)")
        single_signature = True
    elif family:
        kind = f"account owned by {FAMILY_NAMES[family]}"
        single_signature = False
    elif owner is None:
        # Off the curve with no account of its own. This is the ordinary shape
        # of a signing PDA: a program signs for it with invoke_signed and the
        # address never needs to hold anything. Which program can sign is NOT
        # readable from the address — it has to be re-derived, which is what
        # --find-multisig does. Saying "nothing can sign for it" here would be
        # a confident false statement, so this says what is actually known.
        kind = ("program-derived address with no account of its own — some "
                "program can sign for it with invoke_signed; which program "
                "cannot be read off the address (try --find-multisig)")
        single_signature = False
    elif owner == lib.SYSTEM_PROGRAM:
        kind = "off-curve, System-owned (a PDA whose program has not claimed it)"
        single_signature = False
    else:
        kind = f"off-curve, owned by program {owner}"
        single_signature = False

    return {
        "address": address,
        "onCurve": on_curve,
        "exists": account is not None,
        "owner": owner,
        "dataLen": len(account["data"]) if account else 0,
        "lamports": account["lamports"] if account else 0,
        "multisigFamily": family,
        "kind": kind,
        "singleSignatureSuffices": single_signature,
    }


def program_authority_history(program_data_address: str, limit: int = 40,
                              url=None) -> list:
    """Every deploy, upgrade and authority handover this program has seen.

    Read from the transactions that touched the ProgramData account, decoded
    from the raw instruction bytes — the 4-byte instruction tag and the account
    list — rather than from any RPC-side parser or explorer label.

    This exists to be a SECOND, independent source for the current upgrade
    authority. The account says who it is; the history says who it was set to
    and when. If those two disagree, something in this checker is wrong, and a
    reader should be told rather than shown a confident single number.
    """
    signatures = lib.rpc("getSignaturesForAddress",
                         [program_data_address, {"limit": limit}], url=url)
    if not signatures:
        return []

    params = [[s["signature"], {"encoding": "json",
                                "maxSupportedTransactionVersion": 0}]
              for s in signatures]
    # Small batches on purpose: the free public endpoint rate-limits
    # getTransaction hard, and a checker a stranger cannot run is not a checker.
    transactions = lib.rpc_batch("getTransaction", params, url=url, chunk=8)

    events = []
    for meta_sig, tx in zip(signatures, transactions):
        if tx is None:
            events.append({"signature": meta_sig["signature"],
                           "slot": meta_sig.get("slot"),
                           "blockTime": meta_sig.get("blockTime"),
                           "instruction": None,
                           "note": "the endpoint no longer has this transaction"})
            continue

        message = tx["transaction"]["message"]
        keys = list(message["accountKeys"])
        loaded = (tx.get("meta") or {}).get("loadedAddresses") or {}
        keys += list(loaded.get("writable") or []) + list(loaded.get("readonly") or [])
        failed = (tx.get("meta") or {}).get("err") is not None

        for instruction in message["instructions"]:
            program = keys[instruction["programIdIndex"]]
            if program != spl_mint.BPF_UPGRADEABLE_LOADER:
                continue
            data = lib.b58decode(instruction["data"])
            if len(data) < 4:
                continue
            tag = int.from_bytes(data[:4], "little")
            accounts = [keys[i] for i in instruction["accounts"]]
            if program_data_address not in accounts:
                continue

            signer_slot, new_slot = LOADER_IX_AUTHORITY_SLOTS.get(tag, (None, None))
            events.append({
                "signature": meta_sig["signature"],
                "slot": tx.get("slot", meta_sig.get("slot")),
                "blockTime": tx.get("blockTime", meta_sig.get("blockTime")),
                "instruction": LOADER_IX_NAMES.get(tag, f"unknown tag {tag}"),
                "tag": tag,
                "failed": failed,
                "signingAuthority": (accounts[signer_slot]
                                     if signer_slot is not None
                                     and signer_slot < len(accounts) else None),
                # SetAuthority with the third account omitted revokes the
                # authority outright: the program becomes immutable. That is a
                # real, meaningful "None" and is not the same as "not decoded".
                "newAuthority": (accounts[new_slot]
                                 if new_slot is not None and new_slot < len(accounts)
                                 else (None if tag in (4, 7) else "n/a")),
                "accounts": accounts,
            })
    return events


def _stamp(block_time) -> str:
    if not block_time:
        return "unknown time"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(block_time))


def check_program_authority(program_id: str, expect_authorities=None,
                            expect_single_key: bool = False,
                            expect_immutable: bool = False,
                            history: int = 0, url=None, quiet: bool = False):
    """"Who can upgrade program X?" — decoded, classified and cross-checked."""
    out = sys.stderr if quiet else sys.stdout
    checks = lib.Checks()

    if not quiet:
        lib.banner(f"PROGRAM UPGRADE AUTHORITY — {program_id}", url=url, stream=out)

    genesis = lib.rpc("getGenesisHash", [], url=url)
    if genesis != MAINNET_GENESIS:
        raise lib.CheckerError(
            f"this endpoint reports genesis hash {genesis}, which is not "
            f"Solana mainnet-beta ({MAINNET_GENESIS})."
        )
    checks.expect("the endpoint really is Solana mainnet-beta (genesis hash)",
                  genesis, MAINNET_GENESIS)

    info = spl_mint.program_upgrade_authority(program_id, url=url)
    program_data = info.get("programDataAddress")

    # The Program account points at its ProgramData account. Believing that
    # pointer is believing one field of the account we are auditing. The loader
    # also fixes the address by derivation — seeds [program_id] — so it can be
    # recomputed from nothing but the program id and checked against the
    # pointer. If they ever disagreed, the bytes being read would not be this
    # program's.
    if program_data:
        derived_raw, _bump = lib.find_program_address(
            [lib.parse_pubkey(program_id)],
            lib.parse_pubkey(spl_mint.BPF_UPGRADEABLE_LOADER))
        derived = lib.b58encode(derived_raw)
        checks.expect(
            "the ProgramData address re-derives from the program id alone "
            "(seeds [program_id] under the BPF Upgradeable Loader), so the "
            "authority below is read from the right account",
            program_data, derived)

    authority = info.get("upgradeAuthority")
    checks.observe("program data account", program_data)
    checks.observe("last deployed slot", info.get("lastDeployedSlot"))
    checks.observe("upgrade authority",
                   authority or "NONE — the program is immutable")

    classification = None
    if authority:
        classification = classify_authority(authority, url=url)
        checks.observe("what kind of account that authority is",
                       classification["kind"])
        checks.observe("one signature is enough to upgrade this program",
                       "yes" if classification["singleSignatureSuffices"] else "no")

    for expected in (expect_authorities or []):
        checks.expect(f"the upgrade authority is {expected}",
                      authority or "NONE (immutable)", expected)

    if expect_immutable:
        checks.expect_true("the program has no upgrade authority at all",
                           authority is None,
                           "immutable" if authority is None
                           else f"upgradeable by {authority}")

    if expect_single_key:
        checks.expect_true(
            "the upgrade authority is a plain keypair — on the ed25519 curve, "
            "so a private key for it exists and one signature can replace the "
            "program's code",
            bool(classification and classification["onCurve"]),
            "no authority at all (immutable)" if not classification
            else f"{classification['kind']}",
        )
        checks.expect_true(
            "no program stands between that key and an upgrade (the authority "
            "is not owned by a multisig, governance or timelock program)",
            bool(classification and classification["onCurve"]
                 and classification["owner"] in (None, lib.SYSTEM_PROGRAM)),
            "immutable" if not classification
            else f"owner is {classification['owner'] or 'no account'}",
        )

    events = []
    if history:
        events = program_authority_history(program_data, limit=history, url=url)
        control_events = [e for e in events if e.get("instruction")
                          and not e.get("failed")]
        handovers = [e for e in control_events if e["tag"] in (4, 7)]
        upgrades = [e for e in control_events if e["tag"] in (2, 3)]
        checks.observe(f"loader instructions decoded from the last {history} "
                       "transactions touching the program data account",
                       len(control_events))

        # Two reconciliations. Each pits the account's own fields against a
        # completely different source — the transaction log — and neither can
        # see the other.
        if handovers:
            newest = handovers[0]
            checks.expect(
                "the most recent successful SetAuthority in the transaction "
                "history names the same authority the account reports (two "
                "independent sources for the same fact)",
                newest["newAuthority"] or "NONE (revoked)",
                authority or "NONE (revoked)")
            checks.observe("authority last changed",
                           f"{_stamp(newest['blockTime'])} in {newest['signature']}")
        if upgrades:
            checks.expect(
                "the slot of the most recent successful deploy/upgrade "
                "transaction equals the last-deployed slot stored in the "
                "program data account",
                upgrades[0]["slot"], info.get("lastDeployedSlot"))
            checks.observe("code last replaced",
                           f"{_stamp(upgrades[0]['blockTime'])} in "
                           f"{upgrades[0]['signature']}")

    if not quiet:
        print("", file=out)
        print("WHO CAN UPGRADE THIS PROGRAM", file=out)
        print("-" * 70, file=out)
        if authority is None:
            print("  Nobody. The upgrade authority has been revoked.", file=out)
        else:
            print(f"  {authority}", file=out)
            print(f"  {classification['kind']}", file=out)
            print(f"  on the ed25519 curve: {classification['onCurve']}   "
                  f"account exists: {classification['exists']}   "
                  f"owner: {classification['owner'] or 'n/a'}", file=out)
        if events:
            print("", file=out)
            print("LOADER HISTORY (newest first, decoded from instruction bytes)",
                  file=out)
            print("-" * 70, file=out)
            for event in events:
                if not event.get("instruction"):
                    continue
                line = (f"  {_stamp(event['blockTime'])}  slot {event['slot']}  "
                        f"{event['instruction']}")
                if event["tag"] in (4, 7):
                    line += f" -> {event['newAuthority'] or 'REVOKED (immutable)'}"
                if event.get("failed"):
                    line += "   [transaction FAILED — no effect]"
                print(line, file=out)
                print(f"      signed by {event['signingAuthority']}", file=out)
                print(f"      {event['signature']}", file=out)

    facts = {
        "programId": program_id,
        "programDataAddress": program_data,
        "lastDeployedSlot": info.get("lastDeployedSlot"),
        "upgradeAuthority": authority,
        "authorityClassification": classification,
        "expectedAuthorities": list(expect_authorities or []),
        "history": events,
        "checkedAt": lib.utc_now(),
        "assertions": checks.rows,
    }
    return checks, facts


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
        # The account is allocated with room to grow the member list, ten slots
        # at a time, so leftover bytes are normal here and prove nothing on
        # their own. What DOES have to hold is that the whole account is
        # 58 + 32 x capacity bytes with capacity >= the member count: every
        # leftover byte must belong to an unused member slot. That is a real
        # structural assertion — a wrong layout misses the 32-byte grid 31
        # times out of 32 — and unlike the old "leftover must be zero" test it
        # is true of every well-formed v3 account rather than only the ones
        # that happen to be full.
        members_n = len(multisig["members"])
        checks.expect_true(
            "the account size is exactly 58 + 32 x capacity bytes and capacity "
            "is at least the member count (every leftover byte is an unused "
            "member slot, not slack a wrong layout could hide in)",
            multisig["slotAligned"],
            f"{multisig['accountBytes']} bytes = {MS_SIZE_WITHOUT_MEMBERS} + 32 x "
            f"{(multisig['accountBytes'] - MS_SIZE_WITHOUT_MEMBERS) / 32:g} "
            f"for {members_n} members"
            + (f", {multisig['spareMemberSlots']} slot(s) spare"
               if multisig["slotAligned"] else " — NOT on the 32-byte grid"),
        )
        checks.observe("spare member slots (room to add members without a realloc)",
                       multisig["spareMemberSlots"])

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

# A live Squads v3 multisig with SPARE member capacity: Streamflow's, holding
# the upgrade authority of both Streamflow programs (found in wake 10 by
# exhaustive search). 538 bytes = 58 + 32 x 15, five members, ten empty slots.
# This is the account the v3 path used to fail on. It is here so that the
# regression cannot come back unnoticed.
V3_SPARE_MULTISIG = "F8aHkn9zir2Yx2jQbm3QSvRKuibib1WDPKBmPuoXNP8D"

# A program with a long, varied loader history — deploys, upgrades and many
# authority handovers — used to prove that the history decoder's account
# positions are load-bearing. Solend's lending program: 77 loader instructions
# since 2021, including 27 authority changes.
HISTORY_PROGRAM = "So1endDq2YkqhipRh3WViPa8hdiSpxWy6z3Z6tMCpAo"

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

    # -- Control 29: online, POSITIVE. THE REGRESSION THIS WAKE FIXED. A live
    #    Squads v3 multisig with spare member capacity must decode and pass.
    #    Until wake 15 this returned exit 1 — "an assertion is false" — for a
    #    perfectly well-formed account, because the v3 path demanded that zero
    #    bytes be left over. Streamflow's multisig is 538 bytes = 58 + 32 x 15
    #    with five members, so ten slots are empty and always will be until
    #    somebody joins.
    try:
        checks, facts = check(V3_SPARE_MULTISIG, url=url, quiet=True)
        code = checks.exit_code()
        decoded = facts["multisig"]
        spare = decoded["spareMemberSlots"]
        record("KNOWN-GOOD: a live v3 multisig with SPARE member slots passes "
               "(the wake-15 regression)",
               code == 0 and facts["squadsVersion"] == "v3" and spare and spare > 0,
               f"exit code {code} (wanted 0), {decoded['accountBytes']} bytes, "
               f"{len(decoded['members'])} members, {spare} spare slot(s)")
    except lib.CheckerError as exc:
        record("KNOWN-GOOD: a live v3 multisig with SPARE member slots passes "
               "(the wake-15 regression)", False, str(exc), blocked=True)

    # -- Control 30: offline, NEGATIVE. The replacement assertion must still
    #    bite. An Ms account whose length is not 58 + 32k cannot be explained
    #    by unused member slots, and the decoder must say so instead of
    #    shrugging at leftover bytes the way the serum path legitimately does.
    try:
        body = (lib.anchor_discriminator("Ms")
                + (2).to_bytes(2, "little")      # threshold
                + (1).to_bytes(2, "little")      # authority_index
                + (0).to_bytes(4, "little")      # transaction_index
                + (0).to_bytes(4, "little")      # ms_change_index
                + bytes([255])                   # bump
                + bytes(32)                      # create_key
                + bytes([0])                     # allow_external_execute
                + (1).to_bytes(4, "little")      # one member
                + bytes(32))                     # that member
        aligned = decode_multisig_v3(body + bytes(64))     # two empty slots
        skewed = decode_multisig_v3(body + bytes(64) + bytes(5))  # 5 bytes off-grid
        record("KNOWN-BAD: an Ms account that is not 58 + 32k bytes fails the "
               "size assertion, while a whole number of spare slots passes",
               aligned["slotAligned"] and not skewed["slotAligned"],
               f"58+32x3 -> slotAligned={aligned['slotAligned']} "
               f"(spare {aligned['spareMemberSlots']}); "
               f"5 bytes over -> slotAligned={skewed['slotAligned']}")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: an Ms account that is not 58 + 32k bytes fails the "
               "size assertion, while a whole number of spare slots passes",
               False, str(exc))

    # -- Control 31: online, POSITIVE. --program mode on a program known to be
    #    controlled by a Squads v3 authority: the authority must come back
    #    exactly, and must be classified as off-curve rather than as a keypair.
    try:
        checks, facts = check_program_authority(
            V3_CONTROLLED_PROGRAM, expect_authorities=[V3_AUTHORITY],
            url=url, quiet=True)
        code = checks.exit_code()
        classification = facts["authorityClassification"]
        record("KNOWN-GOOD: --program resolves a multisig-controlled program "
               "and classifies its authority as off-curve",
               code == 0 and classification and not classification["onCurve"],
               f"exit code {code} (wanted 0), authority "
               f"{facts['upgradeAuthority']}, onCurve "
               f"{classification and classification['onCurve']} (wanted False)")
    except lib.CheckerError as exc:
        record("KNOWN-GOOD: --program resolves a multisig-controlled program "
               "and classifies its authority as off-curve",
               False, str(exc), blocked=True)

    # -- Control 32: online, NEGATIVE. The same program with --expect-single-key
    #    must FAIL. A PDA is not a keypair, and a checker that cannot tell them
    #    apart cannot answer the question this mode exists for.
    try:
        checks, _ = check_program_authority(
            V3_CONTROLLED_PROGRAM, expect_single_key=True, url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: claiming a PDA-controlled program is under a single "
               "keypair produces exit 1",
               code == 1, f"exit code {code} (wanted 1)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: claiming a PDA-controlled program is under a single "
               "keypair produces exit 1", False, str(exc), blocked=True)

    # -- Control 33: online, NEGATIVE. An immutable program has no authority at
    #    all, so any --expect-authority must fail. "Nobody can upgrade it" is
    #    not "your key can upgrade it", however much safer it sounds.
    try:
        checks, facts = check_program_authority(
            IMMUTABLE_PROGRAM, expect_authorities=[V3_AUTHORITY],
            url=url, quiet=True)
        code = checks.exit_code()
        record("KNOWN-BAD: an authority claimed for an immutable program fails",
               code == 1 and facts["upgradeAuthority"] is None,
               f"exit code {code} (wanted 1), authority "
               f"{facts['upgradeAuthority']} (wanted None)")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: an authority claimed for an immutable program fails",
               False, str(exc), blocked=True)

    # -- Control 34: online. THE ONE THAT MAKES THE HISTORY WORTH READING.
    #    The loader history is decoded from raw instruction bytes: a 4-byte tag
    #    and a fixed account position. Read the new authority from the wrong
    #    account slot and the answer changes — so if the slot were wrong, the
    #    reconciliation against the account's own upgrade-authority field could
    #    not hold. This control proves the slot is load-bearing rather than
    #    decorative, by doing it wrong on purpose against live data.
    try:
        info = spl_mint.program_upgrade_authority(HISTORY_PROGRAM, url=url)
        events = program_authority_history(info["programDataAddress"],
                                           limit=6, url=url)
        handovers = [e for e in events
                     if e.get("tag") in (4, 7) and not e.get("failed")]
        if not handovers:
            record("KNOWN-BAD: reading the new authority from the wrong account "
                   "slot breaks the reconciliation", False,
                   "no authority handover found in the last 6 transactions",
                   blocked=True)
        else:
            right = handovers[0]["newAuthority"]
            wrong_slot = handovers[0]["accounts"][1]      # the SIGNER, not the new authority
            record("KNOWN-BAD: reading the new authority from the wrong account "
                   "slot breaks the reconciliation",
                   right == info["upgradeAuthority"] and wrong_slot != right,
                   f"slot 2 gives {right} which matches the account's own field; "
                   f"slot 1 gives {wrong_slot}, which does not")
    except lib.CheckerError as exc:
        record("KNOWN-BAD: reading the new authority from the wrong account "
               "slot breaks the reconciliation", False, str(exc), blocked=True)

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
    parser.add_argument("--program", metavar="PROGRAM_ID",
                        help="reverse mode: instead of starting from a "
                             "multisig, start from a program and report WHO "
                             "can upgrade it and what kind of account that "
                             "authority is (keypair, multisig vault, PDA).")
    parser.add_argument("--expect-authority", metavar="ADDRESS",
                        action="append", dest="expect_authorities",
                        help="with --program: assert the upgrade authority is "
                             "this address. Repeatable — a docs page that names "
                             "two different authorities gets both tested.")
    parser.add_argument("--expect-single-key", action="store_true",
                        help="with --program: assert the upgrade authority is a "
                             "plain keypair on the ed25519 curve, with no "
                             "program standing between it and an upgrade.")
    parser.add_argument("--expect-immutable", action="store_true",
                        help="with --program: assert the program has no upgrade "
                             "authority at all.")
    parser.add_argument("--history", type=int, nargs="?", const=40, default=0,
                        metavar="N",
                        help="with --program: decode the last N transactions "
                             "touching the program data account (default 40) "
                             "and report every deploy, upgrade and authority "
                             "handover, from the raw instruction bytes.")
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

    if args.program:
        try:
            checks, facts = check_program_authority(
                args.program,
                expect_authorities=args.expect_authorities,
                expect_single_key=args.expect_single_key,
                expect_immutable=args.expect_immutable,
                history=args.history,
                url=args.rpc,
            )
        except lib.CheckerError as exc:
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
