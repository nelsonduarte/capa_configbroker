# capa_hash

Pure-Capa SHA-256, SHA-224, and HMAC-SHA256. Zero capabilities: every
hash is a `(List<Int>) -> ...` or `(String) -> ...` function over
bytes. Nothing here can touch the filesystem, the network, the clock,
randomness, or anything else; the library holds no authority and reads
no global state. `capa --manifest` proves it (see
[Audit claim](#audit-claim)). Output is byte-identical on the Python
and Wasm backends.

These are **reference implementations, verified against the official
NIST FIPS 180-4 and RFC 4231 test vectors**, but **not audited by a
cryptographer**. See [Honest posture](#honest-posture) before relying
on this for anything security-critical.

## Status

v0.1 (seed library). Scope, fixed by design:

- **SHA-256** (FIPS 180-4): hex and raw-byte digest, over bytes or a
  UTF-8 String.
- **SHA-224** (FIPS 180-4): the same compression machine as SHA-256
  with a different initial state and a 28-byte truncation.
- **HMAC-SHA256** (RFC 2104 / RFC 4231): keyed authentication over
  bytes or Strings; keys longer than the 64-byte block are hashed
  first, shorter keys are zero-padded.
- **Constant-time equality** (new in v0.1.1): compare two byte lists
  or two strings (a MAC, an HMAC tag, a one-time code) with no
  early-out and no branch on byte content, carrying the
  `@constant_time` marker. Verifying a tag with `==` is a timing side
  channel (CWE-208); this is the branchless fix.

Out of scope, by design (each is a real decision, not an oversight):

- **SHA-512 / SHA-384.** Their 64-bit lanes do not fit with headroom
  in Capa's signed-i64 `Int` under checked overflow; a correct port
  would need careful split-word arithmetic. Deferred.
- **MD5 and SHA-1.** Cryptographically broken; shipping them invites
  misuse. Not included.
- **Key-derivation functions (PBKDF2, bcrypt, scrypt, Argon2).**
  Password hashing needs a deliberately slow, salted KDF, which is a
  separate design with separate guarantees. **Do not hash passwords
  with a bare SHA** (see below).
- **Ciphers, AEAD, signatures, X.509.** Out of scope entirely.

## Quick start

```capa
import capa_hash.sha256
import capa_hash.hmac
import capa_hash.verify

fun main(stdio: Stdio)
    // Hash a String (its UTF-8 bytes) to lowercase hex.
    stdio.println(sha256_hex_utf8("abc"))
    // -> ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad

    // Hash raw bytes (each 0..255).
    let bytes: List<Int> = [0x61, 0x62, 0x63]
    stdio.println(sha256_hex(bytes))   // same digest

    // Authenticate a message under a shared secret.
    let tag = hmac_sha256_hex_utf8("shared-secret", "the message")
    stdio.println(tag)

    // Verify a tag in CONSTANT TIME (never compare a tag with ==).
    let again = hmac_sha256_hex_utf8("shared-secret", "the message")
    stdio.println("${strings_equal(again, tag)}")   // true
```

The full runnable example is [`example.capa`](./example.capa); it
hashes a String with SHA-256 and SHA-224 and round-trips an HMAC.

```bash
capa --run example.capa
capa --wasm --run example.capa   # byte-identical output
```

## Install via capa.toml

```toml
[dependencies.capa_hash]
git = "https://github.com/nelsonduarte/capa_hash"
tag = "v0.1.1"
verify_key = "6C1D222D491FB88031E041A536CFB426101AA24B"
```

`capa install` runs `git verify-tag` against your GPG keyring; import
the publisher's key first (see [`SECURITY.md`](SECURITY.md) for the
fingerprint provenance and `gpg --import` instructions).

## API surface

### SHA-256 / SHA-224 (from `capa_hash.sha256`)

```capa
pub fun sha256_bytes(message: List<Int>) -> List<Int>   // 32 raw bytes
pub fun sha256_hex(message: List<Int>)   -> String      // 64 hex chars
pub fun sha256_hex_utf8(text: String)    -> String      // hash of text's UTF-8 bytes

pub fun sha224_bytes(message: List<Int>) -> List<Int>   // 28 raw bytes
pub fun sha224_hex(message: List<Int>)   -> String      // 56 hex chars
pub fun sha224_hex_utf8(text: String)    -> String
```

### HMAC-SHA256 (from `capa_hash.hmac`)

```capa
pub fun hmac_sha256_bytes(key: List<Int>, message: List<Int>) -> List<Int>  // 32 raw bytes
pub fun hmac_sha256_hex(key: List<Int>, message: List<Int>)   -> String     // 64 hex chars
pub fun hmac_sha256_hex_utf8(key: String, message: String)    -> String
```

### Constant-time equality (from `capa_hash.verify`)

```capa
@constant_time()
pub fun bytes_equal(a: List<Int>, b: List<Int>) -> Bool  // tag/MAC byte compare
@constant_time()
pub fun strings_equal(a: String, b: String)     -> Bool  // hex digest / OTP compare
```

Use these to verify a MAC, an HMAC tag, or a one-time code against an
**untrusted** value. The ordinary `==` short-circuits at the first
differing byte, so its run time leaks the length of the matching
prefix: an attacker who can measure it forges a valid tag one byte at
a time (CWE-208). `bytes_equal` / `strings_equal` instead XOR every
byte pair and OR-accumulate the differences across the **whole** input
with no early return and no branch on byte content, so the time
depends only on the length, never on where the inputs first differ.

A length mismatch returns `false` at once: a tag's length is fixed by
the algorithm and not secret, so branching on it leaks nothing. Both
functions carry the `@constant_time` marker, which the analyzer proves
(see [Audit claim](#audit-claim)); `strings_equal` is the thin
`String.bytes()` wrapper for tags carried as text (two hex digests,
two base64 tokens). The byte contract of the hash functions applies:
elements outside `0..255` are masked to 8 bits before the compare.
The functions are pure, with zero capabilities, so passing
`@secret`-labelled bytes is fine: the `Bool` result is the only thing
derived, and a pure function with no sinks cannot leak it.

Bytes are `List<Int>`, each element in `0..255`. The `_utf8` wrappers
take a `String` and hash its UTF-8 bytes via the language's
`String.bytes()`. The raw `_bytes` form exists so a caller can compose
(HMAC itself is built on `sha256_bytes`) and so non-text inputs hash
without a String detour.

> **Byte contract (read this if you pass `List<Int>` directly).** Every
> element of a byte input **must be in `0..255`**. A value outside that
> range is **silently masked to its low 8 bits** (`x & 0xFF`), so `256`
> becomes `0` and `-1` becomes `255`; the function does **not** reject
> or report it. The behaviour is identical on both backends. The
> safe path is to derive bytes from a `String` via the `_utf8`
> wrappers or `String.bytes()` (always in range), or from a source you
> have already constrained to `0..255`. Passing arbitrary `Int`s and
> relying on the masking is unsupported and will produce a digest of
> *different* bytes than you intended.

## Implementation notes

SHA-256 is built from the textbook decomposition: a `u32` mask
(`0xFFFFFFFF`), a `rotr32` from shifts and an OR, the 64-word message
schedule, and the 64-round compression, with SHA-224 reusing all of it
behind a different initial state and a 7-word (28-byte) truncation.

Capa's `Int` is a signed 64-bit integer with **checked** overflow: an
add or shift that would exceed `i64` traps rather than wrapping. So the
implementation masks every intermediate back to 32 bits with
`& 0xFFFFFFFF` after each add and rotate, and masks any value to at
most 8 bits before a 24-bit left shift, keeping every product far below
the `i64` ceiling. A right shift of an already-masked, non-negative
word is logical, exactly what SHA needs. There is no `~` operator, so
bitwise NOT is `x ^ 0xFFFFFFFF`. Bitwise operators bind looser than
`+` in Capa, so every masked sum is fully parenthesised.

The compression and schedule functions carry the `@constant_time()`
attribute. They are branchless with respect to their word inputs and
use no division or modulo, so the analyzer accepts the marker and the
manifest records `constant_time: true` for `rotr32`, `shr32`,
`read_word`, `schedule`, and `compress`. See the limits of that
guarantee below.

The constant-time comparison in `capa_hash.verify` carries the same
marker. Its loop bound is the input length (public, not secret), it
indexes by the loop counter (never by a value), and its accumulator is
combined with `|` and `^` only, with no branch on byte content; the
length check and the final `diff == 0` are decisions on public data
(a length, and the function's own returned result), not on a secret.
The analyzer accepts the marker on both `bytes_equal` and
`strings_equal`, and the manifest records `constant_time: true` for
each.

## Verification

The algorithms were written **oracle-first**: a Python reference
([`tools/sha256_ref.py`](./tools/sha256_ref.py)) mirrors the exact
decomposition used in Capa and is validated against Python's
`hashlib` / `hmac` and the official vectors before any Capa code was
written. It is a debug anchor that lives in `tools/`: it is **not Capa
code**, the toolchain only ever loads `.capa` modules, so it is never
parsed, type-checked, or executed and has no effect on a consumer of
this library. (`.gitattributes` also marks `tools/` `export-ignore`,
so it is left out of the SLSA-attested release tarball.) The Capa
suites then re-assert those same official vectors on both backends:

- **SHA-256, FIPS 180-4:** empty string, `"abc"`, the 448-bit message
  (`abcdbcde...nopq`), and the 896-bit two-block message.
- **SHA-224, FIPS 180-4:** the same four messages with the SHA-224
  expected digests.
- **HMAC-SHA256, RFC 4231:** cases 1, 2, 4, 6, and 7, where cases 6
  and 7 use a 131-byte key (larger than the block, exercising the
  hash-the-key-first path).
- **UTF-8 multi-byte** text (Latin-1 accents, CJK, an astral emoji)
  hashed over the same bytes as `hashlib`.
- **Empty input** and a **multi-kilobyte input** (8000 bytes), each
  cross-checked against the Python oracle.
- **Constant-time equality:** equal lists, a difference at the first,
  last, and middle byte, length mismatches, empty pairs, the 8-bit
  mask folding, and the string wrapper over UTF-8 and over a real
  HMAC tag (matching and forged). A functional test cannot observe
  timing, but it pins the property that makes the branchless loop
  correct: the result is right wherever the first difference falls,
  which is exactly what an early-return version would special-case.
  The `@constant_time` marker, proven by `capa --manifest`, supplies
  the branchless-shape half of the guarantee.

```bash
capa test          # Python backend
capa test --both   # Python + Wasm, byte-identical stdout required
```

Current output of `capa test --both`:

```
capa test: 3 file(s) under .../capa_hash/tests [backend: python+wasm]
test_hmac.capa ... ok
test_sha256.capa ... ok
test_verify.capa ... ok
3 test(s): 3 passed, 0 failed
```

`capa_test` is declared under `[dev-dependencies]` with the same
git + tag + verify_key shape as any published dependency, pinned to its
`v0.1.0` tag and verified against the publisher key, so `capa install`
runs the full three-layer check (lockfile SHA + GPG tag signature +
SLSA L2 provenance) on it. Dev-dependencies are resolved only when this
repository is the install root, so a consumer of `capa_hash` never
fetches the test library.

## Audit claim

A hash library is exactly the kind of dependency a supply-chain
attacker wants to own, so this one proves the empty claim about itself.
`capa --manifest` over every library module reports, for every function
in `sha256`, `hmac`, and `tables`:

```
declared_capabilities:                []
transitively_reachable_capabilities:  []
has_unsafe:                           false
user_defined_capabilities:            []
```

0 functions with capabilities, 0 crossing `unsafe`, in every module.
The compression-machine functions and the two comparison functions in
`verify` additionally report `constant_time: true`. The only capabilities anywhere in this
repository are in the example and are the example's own (`Stdio` to
print). A program using `capa_hash` declares only the authority its own
code needs.

## Honest posture

- **Verified, not audited.** The output is checked against the official
  NIST FIPS 180-4 and RFC 4231 vectors and against Python's `hashlib` /
  `hmac` over many inputs, on both backends. It has **not** been
  reviewed by a cryptographer, fuzzed, or hardened against
  implementation attacks beyond what the language model provides.
- **Not for passwords.** SHA-256 and HMAC-SHA256 are fast by design.
  Hashing a password with either is unsafe: it invites brute force. Use
  a purpose-built KDF (Argon2, scrypt, bcrypt, or PBKDF2). Those are
  out of scope here, deliberately.
- **What `@constant_time` does and does not promise.** The marker is a
  language-level guarantee: inside a `@constant_time` function, no
  `@secret`-labelled value may steer a branch, index a memory access,
  or feed a variable-latency `/` or `%`. That rules out the classic
  source-level timing leaks (secret-dependent control flow and
  table-lookup indices). It does **not** promise constant time against
  cache effects, micro-architectural side channels (speculation, port
  contention, prefetch), or the timing behaviour of the backend's
  generated code. For threat models that require microarchitectural
  resistance, this is not sufficient.
- **HMAC tag comparison.** Verify an untrusted tag with
  `capa_hash.verify` (`bytes_equal` / `strings_equal`), never with
  `==`. Those helpers are branchless over byte content and carry the
  `@constant_time` marker, so the source-level prefix-length oracle is
  gone. The same microarchitectural caveat above still applies: the
  marker is a source-level property, not a guarantee about the
  backend's generated code or the CPU's caches.

## License

MIT. See [`LICENSE`](./LICENSE). Release tags are GPG-signed; see
[`SECURITY.md`](./SECURITY.md) for the fingerprint and verification
instructions.
