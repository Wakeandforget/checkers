#!/usr/bin/env python3
"""
_lib.py — the shared toolbox every checker in this folder uses.

This file talks to the Solana blockchain and turns raw bytes into readable
facts. It is not a checker itself; it has no main() and verifies nothing. It is
imported by multisig.py and by every checker written after it.

Design rule, and the only one that really matters here
------------------------------------------------------
**Every function in this file either returns a real answer or raises an error.
None of them ever returns a clean-looking default.**

The nightmare for this project is a checker that prints "PASS" because a
network call quietly returned nothing and an empty result got treated as
"nothing wrong". So there is no `return None` on failure, no `except: pass`,
no `.get(key, "")` standing in for a value that should have been there. If a
fact cannot be established, the code raises CheckerError and the checker
reports "could not check" (exit code 2), which is a completely different
answer from "checked, and it is fine" (exit code 0).

Standard library only. No pip installs, no SDK, no credentials.
"""

import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class CheckerError(Exception):
    """Something stopped us establishing a fact.

    Raised for every failure: bad input, network trouble, an account that does
    not exist, bytes that do not decode. Checkers catch this and exit 2
    ("could not check"), never exit 0 ("checked, all good").
    """


# ---------------------------------------------------------------------------
# Base58 — the alphabet Solana writes addresses in
# ---------------------------------------------------------------------------
# A Solana address is 32 raw bytes. Humans see it as a ~44-character string
# like "8n6HrBJXgsTnSobCAWKJFKpf3mR3ecgy2yzzGcHT4nEX". Base58 is the encoding
# in between. It leaves out characters that look alike (0/O, I/l) so addresses
# survive being read aloud or copied by hand.

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    """Turn raw bytes into a base58 string."""
    if not isinstance(raw, (bytes, bytearray)):
        raise CheckerError(f"b58encode needs bytes, got {type(raw).__name__}")
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, remainder = divmod(number, 58)
        out = B58_ALPHABET[remainder] + out
    # Every leading zero byte is written as a literal "1". Without this,
    # 0x00AB and 0xAB would encode identically.
    for byte in raw:
        if byte != 0:
            break
        out = "1" + out
    return out or "1"


def b58decode(text: str) -> bytes:
    """Turn a base58 string back into raw bytes.

    Raises rather than returning b"" on bad input — an empty byte string would
    sail on through the rest of a checker looking like a valid answer.
    """
    if not isinstance(text, str) or text == "":
        raise CheckerError("b58decode needs a non-empty string")
    number = 0
    for char in text:
        index = B58_ALPHABET.find(char)
        if index < 0:
            raise CheckerError(
                f"{text!r} is not valid base58: the character {char!r} is not "
                "in the alphabet (0, O, I and l are deliberately excluded)"
            )
        number = number * 58 + index
    body = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    leading_zeros = len(text) - len(text.lstrip("1"))
    return b"\x00" * leading_zeros + body


def parse_pubkey(text: str) -> bytes:
    """Decode an address and insist it is exactly 32 bytes.

    Catches the most common typo — a truncated or over-long address pasted
    from somewhere — at the door, instead of three functions later when it
    produces a confusing failure about account data.
    """
    raw = b58decode(text)
    if len(raw) != 32:
        raise CheckerError(
            f"{text!r} decodes to {len(raw)} bytes; a Solana address is always 32. "
            "It is probably truncated or has an extra character."
        )
    return raw


def is_valid_pubkey(text: str) -> bool:
    """True if `text` is a well-formed address. Used for input validation only."""
    try:
        parse_pubkey(text)
        return True
    except CheckerError:
        return False


# The all-zero address. Solana programs use it to mean "unset" / "nobody".
# It is also the address of the System Program.
SYSTEM_PROGRAM = "11111111111111111111111111111111"


# ---------------------------------------------------------------------------
# Program Derived Addresses (PDAs)
# ---------------------------------------------------------------------------
# A PDA is an address calculated from a program and some seed values, chosen
# so that it is NOT a point on the ed25519 curve. That sounds abstract; the
# consequence is concrete and is the whole point: no private key can exist for
# such an address, so nobody — not the developers, not us — can sign for it.
# Only the program itself can move its funds.
#
# We recompute PDAs from scratch here rather than trusting an explorer or an
# API to tell us "this is the vault". Deriving it ourselves is the difference
# between checking a claim and repeating one.

_P = 2 ** 255 - 19                                   # the ed25519 field prime
_D = (-121665 * pow(121666, _P - 2, _P)) % _P        # curve constant
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)                 # square root of -1

PDA_MARKER = b"ProgramDerivedAddress"


def is_on_curve(point: bytes) -> bool:
    """True if these 32 bytes are a valid ed25519 public key (a real address).

    False means no private key can produce it — which is what makes an address
    a PDA rather than a wallet somebody holds.
    """
    if not isinstance(point, (bytes, bytearray)) or len(point) != 32:
        raise CheckerError("is_on_curve needs exactly 32 bytes")
    y = int.from_bytes(point, "little")
    sign = (y >> 255) & 1
    y &= (1 << 255) - 1
    if y >= _P:
        return False
    y2 = (y * y) % _P
    u = (y2 - 1) % _P
    v = (_D * y2 + 1) % _P
    if v == 0:
        return False
    x = (u * pow(v, _P - 2, _P)) % _P
    candidate = pow(x, (_P + 3) // 8, _P)
    if (candidate * candidate - x) % _P != 0:
        candidate = (candidate * _SQRT_M1) % _P
    if (candidate * candidate - x) % _P != 0:
        return False
    if candidate == 0 and sign:
        return False
    return True


def find_program_address(seeds, program_id: bytes):
    """Solana's findProgramAddress, reimplemented from the specification.

    Hash the seeds plus a "bump" byte, counting the bump down from 255, and
    take the first result that is off the curve. Returns (32 bytes, bump).
    """
    if not isinstance(program_id, (bytes, bytearray)) or len(program_id) != 32:
        raise CheckerError("find_program_address needs a 32-byte program id")
    for bump in range(255, -1, -1):
        digest = hashlib.sha256()
        for seed in seeds:
            if not isinstance(seed, (bytes, bytearray)):
                raise CheckerError(f"seed must be bytes, got {type(seed).__name__}")
            digest.update(seed)
        digest.update(bytes([bump]))
        digest.update(program_id)
        digest.update(PDA_MARKER)
        candidate = digest.digest()
        if not is_on_curve(candidate):
            return candidate, bump
    # Mathematically almost impossible. If it ever happens, it is a bug, and a
    # loud failure beats a plausible-looking wrong address.
    raise CheckerError("no off-curve address found for these seeds")


def anchor_discriminator(account_name: str) -> bytes:
    """The 8-byte tag Anchor programs put at the start of every account.

    It is the first 8 bytes of sha256("account:<Name>"). Checking it is how we
    confirm an account really is the type we think before decoding the rest —
    without it, random bytes would decode into confident nonsense.
    """
    if not account_name:
        raise CheckerError("anchor_discriminator needs an account name")
    return hashlib.sha256(f"account:{account_name}".encode()).digest()[:8]


# ---------------------------------------------------------------------------
# Talking to Solana over JSON-RPC
# ---------------------------------------------------------------------------

PUBLIC_RPC = "https://api.mainnet-beta.solana.com"


def rpc_url() -> str:
    """Which Solana server to read the chain through.

    SOLANA_RPC_URL (set from .env by wake.sh) if present, otherwise the free
    public endpoint. The public fallback is deliberate: the constitution
    requires that a stranger with no credentials can re-run any checker here.
    The public endpoint is rate-limited, which is why the agent's own runs use
    a private one.
    """
    return os.environ.get("SOLANA_RPC_URL", "").strip() or PUBLIC_RPC


def mask_url(url: str) -> str:
    """Hide the API key in an endpoint so output can be pasted in public.

    Turns  https://x.helius-rpc.com/?api-key=abc123
    into   https://x.helius-rpc.com/?api-key=<redacted>

    Every place this library prints an endpoint goes through here. A checker's
    output is meant to be published, and the key would otherwise ride along.
    """
    masked = re.sub(r"(?i)((?:api[-_]?key|access[-_]?token|key)=)[^&\s]+",
                    r"\1<redacted>", url)
    # Some providers put the key in the path instead of the query string.
    masked = re.sub(r"(?i)(https?://[^/\s]+/)[A-Za-z0-9_-]{20,}", r"\1<redacted>",
                    masked)
    # A key embedded as https://user:secret@host
    masked = re.sub(r"://[^/@\s]*@", "://<redacted>@", masked)
    return masked


def rpc(method: str, params, url: str = None, timeout: int = 25, attempts: int = 3):
    """Make one JSON-RPC call and return its `result`.

    Retries a few times because public endpoints drop requests under load, then
    gives up by raising. It never returns a placeholder: a checker must not be
    able to mistake "the network was busy" for "the chain says no".
    """
    endpoint = url or rpc_url()
    body = json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    ).encode("utf-8")

    last_error = None
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "content-type": "application/json",
                "user-agent": "verifier-checkers/1 (+https://wakeandforget.com)",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
        except Exception as exc:  # network down, DNS, timeout, bad JSON
            last_error = f"{type(exc).__name__}: {exc}"
        else:
            # The call went through. An `error` member means the server
            # understood us and said no — that is final, so do not retry it.
            if "error" in payload:
                raise CheckerError(
                    f"RPC {method} refused by {mask_url(endpoint)}: {payload['error']}"
                )
            if "result" not in payload:
                raise CheckerError(
                    f"RPC {method} returned no 'result' member: {payload!r:.200}"
                )
            return payload["result"]

        if attempt < attempts:
            time.sleep(attempt)  # 1s, then 2s

    raise CheckerError(
        f"RPC {method} failed after {attempts} attempts against "
        f"{mask_url(endpoint)}: {last_error}"
    )


def get_account(address: str, url: str = None) -> dict:
    """Fetch one account. Raises if it does not exist.

    Returns {"address", "owner", "lamports", "executable", "data" (bytes)}.

    A missing account raises rather than returning an empty dict, because
    "there is nothing at this address" is a real and important finding that
    must reach the reader, not be silently smoothed over.
    """
    if not is_valid_pubkey(address):
        raise CheckerError(f"{address!r} is not a valid Solana address")

    result = rpc("getAccountInfo", [address, {"encoding": "base64"}], url=url)
    value = result.get("value") if isinstance(result, dict) else None
    if value is None:
        raise CheckerError(
            f"no account exists at {address}. Either the address is wrong, or "
            "the account was closed, or this RPC endpoint is behind."
        )
    try:
        raw = base64.b64decode(value["data"][0])
    except Exception as exc:
        raise CheckerError(f"could not decode account data for {address}: {exc}")

    return {
        "address": address,
        "owner": value["owner"],
        "lamports": value["lamports"],
        "executable": value["executable"],
        "data": raw,
    }


LAMPORTS_PER_SOL = 1_000_000_000


def lamports_to_sol(lamports: int) -> str:
    """1 SOL is 1,000,000,000 lamports, the way £1 is 100 pence."""
    return f"{lamports / LAMPORTS_PER_SOL:.9f}"


# ---------------------------------------------------------------------------
# Reading raw account bytes
# ---------------------------------------------------------------------------
# On-chain accounts are a flat run of bytes. Fields sit at fixed offsets in a
# fixed order (the "Borsh" layout). Cursor walks through them in order and
# refuses to read past the end — running off the end of the data is exactly
# how a wrong guess about a layout turns into a confident wrong answer.


class Cursor:
    """Reads fields out of account bytes, one after another, safely."""

    def __init__(self, data: bytes, label: str = "account"):
        if not isinstance(data, (bytes, bytearray)):
            raise CheckerError("Cursor needs bytes")
        self.data = data
        self.offset = 0
        self.label = label

    def take(self, count: int) -> bytes:
        """Read the next `count` bytes, or raise saying exactly where we ran out."""
        if self.offset + count > len(self.data):
            raise CheckerError(
                f"{self.label}: data ended early — wanted {count} bytes at offset "
                f"{self.offset} but the account is only {len(self.data)} bytes. "
                "The layout assumed here probably does not match this account."
            )
        chunk = self.data[self.offset:self.offset + count]
        self.offset += count
        return chunk

    # Unsigned integers, little-endian, in the widths Solana programs use.
    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "little")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "little")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "little")

    def i64(self) -> int:
        return int.from_bytes(self.take(8), "little", signed=True)

    def pubkey(self) -> str:
        return b58encode(self.take(32))

    def option_pubkey(self):
        """An optional address: one flag byte, then the address if the flag is 1."""
        flag = self.u8()
        if flag == 0:
            return None
        if flag != 1:
            raise CheckerError(
                f"{self.label}: expected an option flag of 0 or 1 at offset "
                f"{self.offset - 1}, found {flag}. The layout is wrong."
            )
        return self.pubkey()

    def expect_discriminator(self, account_name: str) -> None:
        """Confirm this account really is the type we are about to decode."""
        found = self.take(8)
        expected = anchor_discriminator(account_name)
        if found != expected:
            raise CheckerError(
                f"this is not a {account_name} account. Its first 8 bytes are "
                f"{found.hex()}, but a {account_name} always starts with "
                f"{expected.hex()} (that is sha256('account:{account_name}')[:8])."
            )

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset


# ---------------------------------------------------------------------------
# Recording what was expected and what was found
# ---------------------------------------------------------------------------


class Checks:
    """Collects the results of a checker so it can print them and pick an exit code.

    Three kinds of row:

      observe(...)  a fact we read off the chain. Not an assertion; it cannot
                    fail. This is most of a report.
      expect(...)   an assertion. Records BOTH the expected value and the found
                    value, so a failure line tells you what the chain actually
                    said rather than just "FAIL".
      blocked(...)  we could not find out. Not a pass and not a fail.

    Exit codes, which are the same in every checker in this project:
      0  everything asserted holds
      1  at least one assertion is false
      2  something could not be checked
    """

    def __init__(self):
        self.rows = []

    def observe(self, label, found):
        self.rows.append({"kind": "observed", "label": label,
                          "found": _stringify(found)})

    def expect(self, label, found, expected) -> bool:
        """Assert `found == expected`. Returns True on pass, False on fail."""
        ok = _stringify(found) == _stringify(expected)
        self.rows.append({
            "kind": "pass" if ok else "fail",
            "label": label,
            "expected": _stringify(expected),
            "found": _stringify(found),
        })
        return ok

    def expect_true(self, label, condition, detail) -> bool:
        """Assert a condition that is not a simple equality."""
        ok = bool(condition)
        self.rows.append({
            "kind": "pass" if ok else "fail",
            "label": label,
            "expected": "true",
            "found": f"{str(ok).lower()} ({detail})",
        })
        return ok

    def blocked(self, label, why):
        self.rows.append({"kind": "blocked", "label": label, "found": str(why)})

    @property
    def any_failed(self) -> bool:
        return any(row["kind"] == "fail" for row in self.rows)

    @property
    def any_blocked(self) -> bool:
        return any(row["kind"] == "blocked" for row in self.rows)

    @property
    def assertions(self) -> list:
        return [r for r in self.rows if r["kind"] in ("pass", "fail")]

    def exit_code(self) -> int:
        if self.any_failed:
            return 1
        if self.any_blocked:
            return 2
        return 0

    def print_report(self, stream=sys.stdout) -> None:
        """Print the assertions. Observations are printed by the checker itself."""
        if not self.assertions and not self.any_blocked:
            print("\nNo assertions were made. Nothing was checked — this is a "
                  "report, not a verdict.", file=stream)
            return
        print("\nASSERTIONS", file=stream)
        print("-" * 70, file=stream)
        for row in self.rows:
            if row["kind"] == "observed":
                continue
            tag = {"pass": "PASS", "fail": "FAIL", "blocked": "NOT CHECKED"}[row["kind"]]
            print(f"  [{tag:>11}] {row['label']}", file=stream)
            if row["kind"] == "blocked":
                print(f"                reason:   {row['found']}", file=stream)
            else:
                print(f"                expected: {row['expected']}", file=stream)
                print(f"                found:    {row['found']}", file=stream)


def _stringify(value) -> str:
    """One consistent text form, so comparing 3 with "3" does the obvious thing."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "none"
    if isinstance(value, (list, tuple)):
        return ", ".join(_stringify(v) for v in value)
    return str(value)


def banner(title: str, url: str = None, stream=sys.stdout) -> None:
    """The header every checker prints: what ran, and against which endpoint."""
    endpoint = url or rpc_url()
    print(title, file=stream)
    print("=" * 70, file=stream)
    print(f"RPC:  {mask_url(endpoint)}", file=stream)
    print(f"Time: {utc_now()}", file=stream)
    print("", file=stream)


def utc_now() -> str:
    """The current time in UTC, in the one format this project uses everywhere."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


# Importing this file directly is a mistake worth catching: it is a library.
if __name__ == "__main__":
    print(__doc__)
    print("This is a library, not a checker. Try:  python3 checkers/multisig.py --help")
    sys.exit(2)
