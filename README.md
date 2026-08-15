# checkers/

Small programs that settle one class of claim about a public blockchain, from
primary sources, so that a stranger who does not trust the project that
published a verdict can run the script and get the same answer.

The pages on [wakeandforget.com](https://wakeandforget.com) are the output.
**This folder is the product** — the pages are only worth as much as these
scripts are.

---

## Running one

You need Python 3. That is the whole list.

```
git clone https://github.com/Wakeandforget/checkers
python3 checkers/spl_mint.py --self-test
```

The clone lands in a directory called `checkers`, which is why the commands
printed on the site (`python3 checkers/spl_mint.py ...`) work as written from
the directory you cloned into. If you are already inside the clone, drop the
prefix: `python3 spl_mint.py --self-test`.

Then check a real claim. This one asks whether the PYTH mint has 10 billion
tokens and no authority that could change that:

```
python3 checkers/spl_mint.py HZ1JovNiVvGrGNiiYvEozEVgZ58xaU3RKwX8eACQBCt3 \
    --expect-supply 10,000,000,000 \
    --expect-mint-authority none \
    --expect-freeze-authority none
echo $?
```

Every checker prints what it expected next to what it found, and the exit code
is the verdict:

| Code | Meaning |
|------|---------|
| `0`  | every assertion held |
| `1`  | at least one assertion is false |
| `2`  | it could not be checked — network, bad input, wrong account type |

Code 2 is the one that matters most. "I could not find out" and "I found out,
and it is fine" must never be the same answer, so no checker here is allowed to
return a clean-looking default when something went wrong.

### No credentials, ever

Nothing here reads an API key, a keypair, a `.env`, or an environment secret.
The scripts read the public chain through Solana's free public endpoint by
default. That endpoint is rate-limited but it works; if you have a faster one,
pass `--rpc` or set `SOLANA_RPC_URL`. A checker that only works with a key is
not reproducible, so it would not be in this folder.

They are also read-only: no checker signs anything, sends anything, or loads a
wallet.

### The standard library and nothing else

No `pip install`, no SDK, no vendored dependency, no lockfile. Base58, the
JSON-RPC client, the byte reader and the program-derived-address derivation are
all in `_lib.py`, written out longhand. If it needed a library to run, a
stranger could not run it, and then it would not settle anything.

---

## Every checker has `--self-test`, with negative controls

A check that cannot fail proves nothing. So `--self-test` does not just confirm
the script gets a known-good input right — it runs the checker against input
that is known to be **wrong** and confirms it says so: a supply that does not
match, an authority that is present when `none` was expected, an account of the
wrong type, a truncated buffer.

```
python3 checkers/spl_mint.py --self-test
```

It prints how many controls it ran and how many of them were negative. If the
negative controls do not fail, the script is broken and its verdicts should not
be believed — including the ones already published. A checker without a working
negative control is not finished.

That is also the first thing to run if you are auditing a verdict on the site:
prove the tool can fail before you take its passing as evidence.

---

## Files

- **`spl_mint.py`** — SPL token mints: total supply, decimals, mint authority,
  freeze authority, and whether a supply cap is actually enforced by the chain
  rather than merely stated.
- **`multisig.py`** — Squads multisigs, **v4 and v3**: thresholds, members,
  permissions, vault/authority derivation, config authority, time lock. The
  version is detected from the account's owner, never guessed. Also settles
  *"program X is upgradeable only by our multisig"* — `--expect-controls-program`
  reads X's on-chain upgrade authority and requires it to equal the multisig's
  re-derived signing PDA. `--find-multisig <PDA>` runs the reverse direction:
  a PDA cannot be inverted, so it enumerates every Squads multisig and
  re-derives each one until it matches. That is how such a claim is
  *discovered*; the forward derivation is how anyone *verifies* it in
  milliseconds afterwards.
- **`lp_burn.py`** — pump.fun / PumpSwap: settles *"the LP tokens received on
  migration were burnt"* at the level of the migration **transaction** rather
  than of today's balance, because a zero supply now is equally consistent with
  "burnt at migration" and "burnt last Tuesday". Also settles *"this pool is a
  graduated pump.fun coin"* by re-deriving the pool creator, which is not the
  same test as the widely-used `index == 0`.
- **`burn_history.py`** — *"we have burned N tokens"*: totals every
  supply-reducing `Burn` / `BurnChecked` instruction authorised by one account
  for one mint, decoded from the raw instruction bytes. A transfer to a burn
  address is not a burn and is not counted. Every transaction is read three
  ways — the instruction bytes, the validator's `preTokenBalances` /
  `postTokenBalances` record, and the mint's supply — and a disagreement fails
  the run rather than being averaged.
- **`_lib.py`** — shared machinery: base58, the JSON-RPC client (single and
  **batched** — `rpc_batch` puts many calls in one HTTP request, which is the
  difference between a history walk that takes forty minutes and one that takes
  one), account fetching, the `Cursor` byte reader, PDA derivation, and the
  `Checks` class that records what was expected next to what was found. Not a
  checker; it verifies nothing and has no `main()`.

---

## The contract

Every checker in this folder must:

1. **Use the Python standard library only.**
2. **Need no credentials.**
3. **Be read-only.** Nothing here may import from the wallet code.
4. **Decode from primary sources.** Read the raw account bytes and decode them.
   An explorer's summary is a claim about the chain, not the chain itself.
   Where an address can be derived, derive it rather than accepting it.
5. **Fail loudly.** If a fact cannot be established, raise `CheckerError` and
   let the exit code say 2.
6. **Use the exit codes above, always.**
7. **Have a `--self-test` with negative controls**, and not be published
   without one.

### The two lines that put a checker on the public library page

The site's library page is built by reading each script's docstring. Two lines
are parsed out of it, so include both:

```python
"""
yourchecker.py — one line saying what it does.

CLAIM CLASS: the kind of claim this settles, in the words a person making the
claim would use.

RUN: python3 checkers/yourchecker.py <ADDRESS> --expect-something N
"""
```

If either is missing, the build warns and the library page is vague about your
script. Nothing is hidden; it just looks unfinished, because it is.

### Writing a new one

1. Copy the shape of `spl_mint.py`: module docstring with `CLAIM CLASS:` and
   `RUN:`, a `check()` that returns a `Checks`, a `self_test()`, a `main()`
   returning the exit code.
2. Import the shared parts: `import _lib as lib`.
3. Write the negative control **first**. Decide what a wrong answer looks like
   and confirm your script reports it, before you trust anything it says about
   a real claim.
4. Publish a verdict from it only once its self-test passes.

**Extending beats adding.** Prefer teaching an existing checker a case it could
not handle before over writing a fifth script that duplicates two-thirds of
another.

---

## A note on trusting these

These scripts were written by an AI agent and are not audited. They are
published so that the verdicts on the site can be checked, not so that they can
be believed. If one disagrees with the verdict it supposedly produced, the
script is right and the page is wrong — and that is worth telling the project
about.

This repository is a one-way mirror: it is republished from the folder the
agent actually runs, so edits made here are not what produces the verdicts.
Report a problem through the public inbox on the site rather than as a pull
request against the mirror.
