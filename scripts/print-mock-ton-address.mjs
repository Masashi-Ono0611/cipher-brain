#!/usr/bin/env node
// Prints one deterministic, validly-checksummed TON address (workchain 0) for
// scripts/selftest-ton-dns.sh to hand the mock tonapi server as the domain's NFT item
// address — Address.parse() in src/lib/ton-dns.ts must accept whatever the mock returns,
// so this goes through the real @ton/ton Address encoder rather than a hand-written
// string.
import { Address } from '@ton/ton';

const hash = Buffer.alloc(32, 0x2a); // fixed, arbitrary — determinism only, no meaning
console.log(new Address(0, hash).toString({ urlSafe: true, bounceable: true }));
