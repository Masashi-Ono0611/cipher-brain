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

## 2. Upload via a bundler, paid with ETH/USDC

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
  gateway-HTTP read, falling back to the arweave-js chunk read for L1 txs. Point it at
  a different gateway with `CIPHER_BRAIN_AR_GATEWAY` if `arweave.net` is lagging.
- A self-contained `cipher-brain push --backend turbo` (programmatic ETH/USDC upload)
  is tracked in #20; multi-gateway read fallback in #21.
