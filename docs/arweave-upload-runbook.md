# Putting an encrypted snapshot on Arweave (and pulling it back)

The durable, censorship-resistant home for a snapshot is **Arweave** (pay-once,
permanent — see [`durability.md`](durability.md)). You don't need an exchange or
native AR: a **bundler (Turbo / ArDrive)** takes **ETH or USDC** via wallet-connect,
and uploads **under 100 KB are free**. This runbook is the path proven end-to-end
this far (a real `dream_verdicts` slice, retrieved from a public gateway and
decrypted — at $0).

## 1. Encrypt (storage only ever sees ciphertext)

```sh
cipher-brain snapshot --pg "<conn>" --pg-table <small_table> --out slice.age   # a small slice (<100KB ⇒ free dry-run)
# or the full brain:  cipher-brain snapshot --pg "<conn>" --dir ~/.gbrain --out brain.age
```

The recipient (public key) is all the snapshotting box needs; the private identity
that decrypts stays off it.

## 2. Upload via a bundler

Two ways to fund and sign the upload — pick ONE:

- **Option A: browser (ArDrive + MetaMask)** — good for a one-off upload from a
  laptop with a MetaMask wallet already funded in ETH/USDC. No local JWK file.
- **Option B: CLI (`cipher-brain wallet` + `push --backend turbo`)** — good for
  `schedule install`'s unattended pushes, or any push run from the machine that
  ran `snapshot`. Signs with a local JWK file cipher-brain generates for you.

### Option A: browser (ArDrive + MetaMask)

1. Open **https://app.ardrive.io** → **Log In → Continue with MetaMask** (signs a
   message; derives an Arweave wallet from your Ethereum wallet — no key export).
2. **Use a PUBLIC drive.** A *private* ArDrive drive re-encrypts the file with a
   wallet-derived key, which **double-wraps our age ciphertext** and breaks the
   "any public gateway + your age key" retrieval. Our file is already encrypted, so
   "public" only ever exposes ciphertext.
3. **Upload** `slice.age` / `brain.age`. Under 100 KB is **free**; larger pays Turbo
   Credits (top up with ETH/USDC, Ethereum L1 or Base).
4. Open the file's details and copy its **Data Tx ID** — the 43-char Arweave id that
   serves the bytes. *Not* the **Metadata Tx ID**, and *not* the ArFS **File ID**
   (a UUID).

### Option B: CLI (`--backend turbo` / `--backend arweave`)

For large blobs (the full brain) the browser is heavy — upload straight from the
host instead. `push` signs with a **JWK file** at `CIPHER_BRAIN_AR_WALLET` — a
DIFFERENT wallet from ArDrive's MetaMask-derived one above, so generate it with
cipher-brain itself and you always know exactly which address you are funding:

```sh
cipher-brain wallet create                 # writes $CIPHER_BRAIN_HOME/wallet.json (0600, no-clobber)
cipher-brain wallet address                # prints the address to fund — the SAME one push will sign with
```

Fund that address — either send it AR/ETH/USDC directly, or top it up with a card at
[turbo.ar.io](https://turbo.ar.io) or [app.ardrive.io](https://app.ardrive.io)
(Turbo natively supports fiat top-up, see `getFiatToAR` in `src/lib/backends/turbo.ts`).
Then push — it prints the data item id, no browser needed:

```sh
npm install @ardrive/turbo-sdk                      # optional, heavy — only for this backend
CIPHER_BRAIN_AR_WALLET=~/.cipher-brain/wallet.json \
  cipher-brain push --in brain.age --backend turbo  # <100KB free; larger spends Turbo Credits
```

The signer is the JWK at `CIPHER_BRAIN_AR_WALLET`. A paid (>100 KB) upload spends Turbo
Credits, and Turbo charges the **signer's** reachable credits — so they must be one of:

- **The JWK's own balance** — fund the JWK's address at [turbo.ar.io](https://turbo.ar.io)
  (connect it via an Arweave wallet and pay by card, or send it native AR).
- **A shared (delegated) approval** — Credits are *non-transferable*, so credits bought on
  a wallet you can't sign with from the CLI (e.g. a MetaMask-derived wallet) can't be moved
  to the JWK. Instead that wallet **shares** an approval to the JWK's address at
  [turbo.ar.io](https://turbo.ar.io), and you pass the sharing wallet's address as
  `CIPHER_BRAIN_AR_PAID_BY` (the `x-paid-by` header) so the upload draws from the approval:

  ```sh
  CIPHER_BRAIN_AR_WALLET=~/.cipher-brain/wallet.json \
  CIPHER_BRAIN_AR_PAID_BY=<address-that-shared-credits> \
    cipher-brain push --in brain.age --backend turbo
  ```

The printed id is the **Data Tx ID**.

> **Treat the JWK as a spend-capable bearer key.** While any Credit Share Approval names
> its address, whoever holds the JWK can spend those credits — it is not "low value". So:
> `chmod 600` it (cipher-brain warns on a group/other-readable wallet); keep it in the
> 0700 `~/.cipher-brain` dir; never commit it (the repo `.gitignore` covers `*wallet*.json`
> / `*.jwk`, but verify before pushing). When sharing an approval, **bound its amount and
> expiry** at [turbo.ar.io](https://turbo.ar.io), and **revoke it after the upload** so a
> later leak of the JWK can't drain the sharer's credits.

## 3. Pull it back from a public gateway (no wallet)

```sh
cipher-brain pull --backend arweave --locator <DATA_TX_ID> --out got.age --wait 1200
```

A fresh bundled upload takes **~5–8 min** to propagate to the gateway (bundle → mine
→ index); `--wait <seconds>` retries until it's retrievable. `pull` streams the body
straight to disk, so a multi-hundred-MB brain doesn't load into memory.

## 4. Verify / restore

```sh
cipher-brain verify  --in got.age                          # asserts it decrypts with YOUR identity
cipher-brain restore --in got.age --out-dir ./restored     # decrypt + extract (add --pg to pg_restore)
```

`verify` PASS ⇒ the bytes on Arweave are your exact ciphertext **and** your identity
decrypts them. That is the whole claim: public + permanent + unreadable without your key.

## Notes

- **Read robustness**: `get()` reads ANS-104 *bundled* items (the bundler form) via a
  gateway-HTTP read, falling back to the arweave-js chunk read for L1 txs. It tries
  **multiple public gateways in turn** (`arweave.net`, then `permagate.io`) so one lagging
  gateway doesn't fail the pull; override the list with `CIPHER_BRAIN_AR_GATEWAYS`
  (comma-separated) or pin one with `CIPHER_BRAIN_AR_GATEWAY`.
- `cipher-brain push --backend turbo` (the CLI upload above) is operator-proven against
  real Arweave by `node scripts/turbo-roundtrip.mjs` (a free <100 KB upload → pull →
  decrypt; needs `@ardrive/turbo-sdk` + a JWK at `CIPHER_BRAIN_AR_WALLET`).
