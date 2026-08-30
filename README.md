# MCrypt

A full OOP cryptography framework for [nanos world](https://nanos.world) written in Lua, exposed globally under the `MCrypt` namespace.

> Made with <3 by Morax/Avada :)

---

## Table of contents

- [Installation & architecture](#installation--architecture)
- [Security at a glance](#security-at-a-glance)
- [Which algorithm should I use?](#which-algorithm-should-i-use)
- [MCrypt.Class](#mcryptclass)
- [MCrypt.Utility](#mcryptutility)
  - [Conversions](#mcryptutilityconversions)
  - [Random](#mcryptutilityrandom)
  - [Base64](#mcryptutilitybase64)
- [MCrypt.Hash](#mcrypthash)
  - [SHA2](#mcrypthashsha2)
  - [SHA512](#mcrypthashsha512)
  - [SHA3](#mcrypthashsha3)
  - [BLAKE3](#mcrypthashblake3)
  - [HMAC](#mcrypthashhmac)
  - [KMAC](#mcrypthashkmac)
  - [Poly1305](#mcrypthashpoly1305)
  - [MD5](#mcrypthashmd5)
- [MCrypt.Encrypt](#mcryptencrypt)
  - [ChaCha20](#mcryptencryptchacha20)
  - [XOR](#mcryptencryptxor)
  - [AES](#mcryptencryptaes)
  - [AEAD](#mcryptencryptaead)
  - [Cipher](#mcryptencryptcipher)
- [MCrypt.Checksum](#mcryptchecksum)
  - [CRC32](#mcryptchecksumcrc32)
  - [Adler32](#mcryptchecksumadler32)
- [MCrypt.Sign](#mcryptsign)
  - [EdDSA](#mcryptsigneddsa)
- [The "byte string" convention](#the-byte-string-convention)

---

## Installation & architecture

```
Packages/mcrypt/
├── Package.toml
├── Server/
├── Client/
└── Shared/
    ├── Index.lua
    ├── Core/
    │   └── Class.lua
    └── Modules/
        ├── Init.lua
        ├── Utility/
        │   ├── Conversions.lua
        │   ├── Random.lua
        │   └── Base64.lua
        ├── Hash/
        │   ├── SHA2.lua
        │   ├── SHA512.lua
        │   ├── SHA3.lua
        │   ├── BLAKE3.lua
        │   ├── HMAC.lua
        │   ├── KMAC.lua
        │   ├── Poly1305.lua
        │   └── MD5.lua
        ├── Encrypt/
        │   ├── ChaCha20.lua
        │   ├── XOR.lua
        │   ├── AES.lua
        │   ├── AEAD.lua
        │   └── Cipher.lua
        ├── Checksum/
        │   ├── CRC32.lua
        │   └── Adler.lua
        └── Sign/
            └── EdDSA.lua
```

`MCrypt` is exposed globally (`_G.MCrypt`) and via `Package.Export("MCrypt", MCrypt)` as soon as `Shared/Index.lua` has loaded so it's directly usable from any Client/Server/Shared file in this package or in any other package that depends on it.

```lua
local hash = MCrypt.Hash.SHA2.SHA256("Hello World!")
```

**Runtime assumption**: Lua 5.4 (native 64-bit integers, bitwise operators `& | ~ << >>`).

---

## Security at a glance

Read this table before picking an algorithm. "Bits" always refers to the **key** unless stated otherwise.

| Module | Rating | Key size | IV / Nonce size | Output / Tag size | Notes |
|---|:---:|---|---|---|---|
| `Encrypt.AEAD` (ChaCha20-Poly1305) | ✅ **Secure recommended default** | 32 bytes (256-bit) | 12 bytes (96-bit) | 16-byte tag | Confidentiality **and** integrity in one call. Prefer this over raw `AES`/`ChaCha20` unless you have a specific reason not to. |
| `Encrypt.AES` (CBC / CTR) | ✅ Secure **but no built-in authentication** | 16 / 24 / 32 bytes (128 / 192 / 256-bit) | 16 bytes (128-bit) | - | Pair with `Hash.HMAC` (encrypt-then-MAC) if you use raw AES and need tamper detection. `AEAD` already does this for you. |
| `Encrypt.ChaCha20` | ✅ Secure **but no built-in authentication** | 32 bytes (256-bit) | 12 bytes (96-bit) | - | Same caveat as AES pair with `Hash.HMAC` or just use `AEAD`. |
| `Encrypt.XOR` | ❌ **Not secure** | any length | - | - | Trivially broken by frequency analysis / known-plaintext attacks. Light obfuscation only, **never** use for anything that actually needs to stay secret. |
| `Sign.EdDSA` (Ed25519) | ✅ Secure | 32-byte public / 64-byte private | - | 64-byte signature | Industry-standard signature scheme. Good for player identity, auth tokens, save-data integrity proofs. |
| `Hash.SHA2` / `SHA512` / `SHA3` / `BLAKE3` | ✅ Secure (as general-purpose hashes) | - | - | 28–64 bytes (variant-dependent) | **Not** suitable for password storage as-is (see below), they're fast by design which is the opposite of what password hashing needs. |
| `Hash.HMAC` / `KMAC` | ✅ Secure MAC | any length (≥ block size recommended) | - | 32–64 bytes (configurable for KMAC) | Use to authenticate messages / verify integrity when both sides share a secret key. |
| `Hash.Poly1305` | ✅ Secure, **one-time only** | 32 bytes (256-bit) | - | 16-byte tag | Never reuse a key across two different messages this breaks the security proof entirely. Already used correctly internally by `Encrypt.AEAD`, use the raw module directly only if you know what you're doing. |
| `Hash.MD5` | ❌ **Cryptographically broken** | - | - | 16 bytes (128-bit) | Practical collision attacks exist. Legacy interop / non-security checksums **only** never for passwords, signatures or integrity you actually rely on. |
| `Checksum.CRC32` / `Adler32` | ⚠️ **Not cryptographic at all** | - | - | 4 bytes (32-bit) | Designed to catch accidental corruption (bad downloads, disk errors), not tampering by an adversary. Trivial to forge on purpose. |
| `Utility.Random` | ⚠️ Software PRNG, **not a hardware CSPRNG** | - | - | - | Fine for nonces, salts, session IDs. Be aware nanos world's Lua doesn't expose an OS-level CSPRNG, so this mixes multiple entropy sources as a best effort it is not a formally proven unpredictable source. |

### ⚠️ Important: password storage

**None of the hash functions in this framework (`SHA2`, `SHA512`, `SHA3`, `BLAKE3`, `MD5`) are appropriate for hashing player passwords.** They're all *fast* cryptographic hashes great for integrity/fingerprinting, terrible for passwords, because a fast hash lets an attacker who steals your database brute-force it at billions of guesses per second on commodity hardware. Password hashing needs a deliberately *slow*, memory-hard algorithm (Argon2, scrypt, bcrypt), **none of which are currently implemented in MCrypt**. If you need to store player credentials, use a dedicated password-hashing library/service or keep using platform-native auth (Steam/Epic) instead of storing passwords yourself. `Sign.EdDSA` (challenge-response, see the example further down) is the recommended way to authenticate players within MCrypt, since it avoids storing any password-equivalent secret server-side at all.

---

## Which algorithm should I use?

| I need to... | Use |
|---|---|
| Encrypt player save data / sensitive config at rest | `Encrypt.AEAD` (confidentiality + integrity in one call) |
| Encrypt a network payload where you already have your own integrity check | `Encrypt.AES` (CTR for streaming, CBC otherwise) or `Encrypt.ChaCha20` |
| Authenticate a player without storing a password | `Sign.EdDSA` (challenge-response) |
| Verify a message wasn't tampered with, using a shared secret | `Hash.HMAC` or `Hash.KMAC` |
| Fingerprint/deduplicate data, generate a content hash | `Hash.BLAKE3` (fastest of the secure hashes) or `Hash.SHA2`/`SHA3` |
| Derive a subkey from a master secret | `Hash.BLAKE3.DeriveKey` |
| Detect *accidental* corruption (not tampering) | `Checksum.CRC32` or `Checksum.Adler32` |
| Generate a random token, nonce or salt | `Utility.Random.Bytes` / `.String` |
| Match an external system's MD5 checksums (legacy interop) | `Hash.MD5` and nothing else |
| Lightly obfuscate non-sensitive data (not a security boundary) | `Encrypt.XOR` and nothing sensitive |

---

## MCrypt.Class

Internal OOP engine used by every stateful module (`AES`, `ChaCha20`, `XOR`, `EdDSA.Key`, `BLAKE3`, `Cipher`).

| Method | Description |
|---|---|
| `MCrypt.Class.New(name, parent?)` | Creates a new class. `parent` is optional, for inheritance. Instances are created by calling the class like a function: `MyClass(...)` which automatically invokes `Constructor` if defined. |
| `MCrypt.Class.Is(instance, class)` | Returns `true` if `instance` is an instance of `class` (or a parent class in the inheritance chain). |
| `MCrypt.Class.GetName(obj)` | Returns the name (string) of a class or instance. |

```lua
local Animal = MCrypt.Class.New("Animal")
function Animal:Constructor(name) self.Name = name end

local dog = Animal("Rex")
print(MCrypt.Class.Is(dog, Animal)) -- true
```

---

## MCrypt.Utility

### MCrypt.Utility.Conversions

Byte-string <> hex <> byte-array conversions. See [The "byte string" convention](#the-byte-string-convention).

| Method | Signature | Description |
|---|---|---|
| `ToHex` | `(data: string) > hex: string` | Converts a byte string to lowercase hex. |
| `FromHex` | `(hex: string) > data: string` | Converts a hex string (even length) back to a byte string. |
| `ToByteArray` | `(data: string) > bytes: integer[]` | Converts to an array of numeric values (0-255). |
| `FromByteArray` | `(bytes: integer[]) > data: string` | Reverse operation. |
| `ByteToHex` | `(value: integer) > hex: string` | Converts a single byte (0-255) to a 2-character hex string. |

### MCrypt.Utility.Random

⚠️ Software PRNG (mixes several entropy sources) **not a hardware CSPRNG**. Good enough for nonces/salts/IDs, reconsider if you need provably unpredictable long-term key material.

| Method | Signature | Description |
|---|---|---|
| `Bytes` | `(length: integer) > data: string` | Generates `length` random bytes. |
| `String` | `(length: integer, alphabet?: string) > string` | Random string (alphanumeric by default). |
| `Integer` | `(min: integer, max: integer) > integer` | Random inclusive integer. |

### MCrypt.Utility.Base64

Standard RFC 4648 (alphabet `A-Za-z0-9+/`, `=` padding). Not encryption this is an encoding, providing zero confidentiality.

| Method | Signature | Description |
|---|---|---|
| `Encode` | `(data: string) > encoded: string` | Encodes a byte string as Base64. |
| `Decode` | `(encoded: string) > data: string` | Decodes Base64 back to a byte string. |

---

## MCrypt.Hash

### MCrypt.Hash.SHA2

✅ Secure. SHA-224 / SHA-256 (FIPS 180-4).

| Method | Signature | Output size | Description |
|---|---|---|---|
| `SHA256` | `(message: string, salt?: string) > hex` | 32 bytes / 256-bit (64 hex chars) | `salt` if given, is appended after the message before hashing. |
| `SHA224` | `(message: string, salt?: string) > hex` | 28 bytes / 224-bit (56 hex chars) | |

### MCrypt.Hash.SHA512

✅ Secure. SHA-384 / SHA-512 (FIPS 180-4, 64-bit word variant).

| Method | Signature | Output size | Description |
|---|---|---|---|
| `SHA512` | `(message: string, salt?: string) > hex` | 64 bytes / 512-bit (128 hex chars) | |
| `SHA384` | `(message: string, salt?: string) > hex` | 48 bytes / 384-bit (96 hex chars) | |

### MCrypt.Hash.SHA3

✅ Secure. Keccak-f[1600] / FIPS 202. Includes fixed-output SHA-3 and SHAKE (extendable-output).

| Method | Signature | Output size | Description |
|---|---|---|---|
| `SHA3_224` | `(message: string) > hex` | 28 bytes / 224-bit | |
| `SHA3_256` | `(message: string) > hex` | 32 bytes / 256-bit | |
| `SHA3_384` | `(message: string) > hex` | 48 bytes / 384-bit | |
| `SHA3_512` | `(message: string) > hex` | 64 bytes / 512-bit | |
| `SHAKE128` | `(message: string, outputBytes: integer) > hex` | your choice | XOF output length is free. |
| `SHAKE256` | `(message: string, outputBytes: integer) > hex` | your choice | XOF output length is free. |

`MCrypt.Hash.SHA3.Internal` also exposes the raw Keccak/cSHAKE primitives (`CShakeRaw`, `LeftEncode`, `RightEncode`, `EncodeString`, `BytePad`, `ToHex`) internal use only (consumed by `Hash.KMAC`), not a stable API for direct consumption.

### MCrypt.Hash.BLAKE3

✅ Secure. The only `Hash` module that's instance/streaming-based. Supports 3 modes: default hash, keyed hash (`KEYED`) and key derivation (`DERIVE_KEY`). XOF output length is free.

**Instance (`MCrypt.Hash.BLAKE3(mode?, keyOrContext?)`)**

| Method | Signature | Description |
|---|---|---|
| `Constructor` | `(mode?: "KEYED"\|"DERIVE_KEY", keyOrContext?: string)` | No arguments: default mode. `"KEYED"` requires a 32-byte key. `"DERIVE_KEY"` takes a context string. |
| `:Update` | `(data: string) -> self` | Feeds the hasher (chainable, streaming). |
| `:Digest` | `(outputBytes?: integer) -> raw bytes` (default 32) | Finalizes. Does **not** invalidate the instance you can `:Update`/`:Digest` again afterward. |
| `:Hex` | `(outputBytes?: integer) -> hex` | Same as `Digest`, hex-encoded. |

**Static (one-shot)**

| Method | Signature | Description |
|---|---|---|
| `BLAKE3.Hash` | `(data: string, outputBytes?: integer) > hex` | Default hash, one-shot. |
| `BLAKE3.Keyed` | `(key: string[32 bytes], data: string, outputBytes?: integer) > hex` | Keyed hash, one-shot. |
| `BLAKE3.DeriveKey` | `(context: string, keyMaterial: string, outputBytes?: integer) > hex` | Key derivation (KDF), one-shot. `context` should be a unique, application-specific constant string. |

```lua
-- Streaming
local h = MCrypt.Hash.BLAKE3()
h:Update("Hello "):Update("World!")
print(h:Hex())

-- One-shot
print(MCrypt.Hash.BLAKE3.Hash("Hello World!"))
```

### MCrypt.Hash.HMAC

✅ Secure MAC. RFC 2104 generic construction plus ready-made shortcuts.

| Method | Signature | Description |
|---|---|---|
| `Compute` | `(message: string, key: string, hashFn: function, blockSize: integer) > hex` | Generic HMAC with any hash function shaped `(message) > hex`. `blockSize` is the underlying hash's block size in bytes. |
| `SHA256` / `SHA224` | `(message: string, key: string) -> hex` | Shortcuts (block size 64 bytes). Key of any length works, a key ≥ block size is recommended for maximum strength. |
| `SHA512` / `SHA384` | `(message: string, key: string) -> hex` | Shortcuts (block size 128 bytes). |

### MCrypt.Hash.KMAC

✅ Secure MAC. NIST SP 800-185 a Keccak-native keyed MAC (not hash-then-MAC like HMAC).

| Method | Signature | Description |
|---|---|---|
| `KMAC128` | `(key: string, message: string, outputBytes?: integer, customization?: string) > hex` | Default output: 32 bytes (256-bit). `customization` is an optional domain-separation string. |
| `KMAC256` | `(key: string, message: string, outputBytes?: integer, customization?: string) > hex` | Default output: 64 bytes (512-bit). |

### MCrypt.Hash.Poly1305

✅ Secure, but **strictly one-time-use**. RFC 8439.

⚠️ **Never reuse a key across two different messages** doing so completely breaks the security guarantee (an attacker can recover part of the key). This is why `Encrypt.AEAD` derives a fresh one-time key per message internally instead of letting you pass a long-term key directly.

| Method | Signature | Key size | Output size | Description |
|---|---|---|---|---|
| `Compute` | `(message: string, key: string[32 bytes]) > tag: string[16 bytes]` | 32 bytes / 256-bit | 16 bytes / 128-bit | Computes the tag. |
| `Verify` | `(message: string, key: string[32 bytes], tag: string[16 bytes]) > boolean` | 32 bytes / 256-bit | - | Verifies a tag (short-circuit-resistant comparison). |

### MCrypt.Hash.MD5

❌ **Cryptographically broken.** Practical collision attacks are well-documented and cheap to run. Provided for legacy interop / non-security checksums **only** never for passwords, signatures or any integrity check you actually rely on.

| Method | Signature | Output size | Description |
|---|---|---|---|
| `Compute` | `(message: string) > hex` | 16 bytes / 128-bit (32 hex chars) | MD5 digest. |

---

## MCrypt.Encrypt

### MCrypt.Encrypt.ChaCha20

✅ Secure stream cipher, **no built-in authentication**. RFC 8439. `Encrypt`/`Decrypt` are the exact same operation.

⚠️ **Never reuse the same (key, nonce) pair for two different messages** this completely breaks confidentiality (the keystream repeats and can be XORed out).

| Method | Signature | Key size | Nonce size | Description |
|---|---|---|---|---|
| `Constructor` | `(key: string[32 bytes], nonce: string[12 bytes], counter?: integer)` | 32 bytes / 256-bit | 12 bytes / 96-bit | `counter` defaults to 0. |
| `:Encrypt` / `:Decrypt` | `(data: string) > string` | - | - | XORs against the keystream (identical operation both ways). |
| `ChaCha20.Once` | `(data: string, key: string[32], nonce: string[12], counter?: integer) > string` | 32 bytes | 12 bytes | One-shot helper. |

### MCrypt.Encrypt.XOR

❌ **Not cryptographically secure.** Trivially broken by frequency analysis and known-plaintext attacks. Light obfuscation only **never** use it for anything that actually needs to stay confidential. Use `AES` or `ChaCha20` (or `AEAD`) instead.

| Method | Signature | Key size | Description |
|---|---|---|---|
| `Constructor` | `(key: string)` | any non-empty length | |
| `:Encrypt` / `:Decrypt` | `(data: string) > string` | - | Repeating-key XOR (identical operation both ways). |
| `XOR.Once` | `(data: string, key: string) > string` | any non-empty length | One-shot helper. |

### MCrypt.Encrypt.AES

✅ Secure, **no built-in authentication**. AES-128/192/256 (FIPS-197), CBC (PKCS7-padded) and CTR modes.

⚠️ IV/counter must never be reused with the same key. This module provides confidentiality only pair it with `Hash.HMAC` (encrypt-then-MAC) if you need tamper detection or use `Encrypt.AEAD` instead if you're starting fresh.

| Method | Signature | Key size | IV size | Description |
|---|---|---|---|---|
| `Constructor` | `(key: string[16\|24\|32 bytes], mode?: "CBC"\|"CTR")` | 16 / 24 / 32 bytes → AES-128 / 192 / 256 | - | `mode` defaults to `"CBC"`. |
| `:EncryptCBC` | `(data: string, iv: string[16 bytes]) > ciphertext: string` | - | 16 bytes / 128-bit | Automatic PKCS7 padding. |
| `:DecryptCBC` | `(data: string, iv: string[16 bytes]) > plaintext: string` | - | 16 bytes | Automatic PKCS7 unpadding. |
| `:CryptCTR` | `(data: string, nonce: string[16 bytes]) > string` | - | 16 bytes | Symmetric (encrypt = decrypt). No padding. |
| `:Encrypt` / `:Decrypt` | `(data: string, ivOrNonce: string[16 bytes]) > string` | - | 16 bytes | Dispatches to CBC or CTR based on the mode set at construction. |
| `AES.GenerateIV` | `() > string[16 bytes]` | - | - | Random IV/nonce via `Utility.Random`. |

### MCrypt.Encrypt.AEAD

✅ **Secure recommended default for encryption.** ChaCha20-Poly1305 (RFC 8439 §2.8): confidentiality **and** integrity/authenticity in one call, with optional associated data (AAD) that is authenticated but not encrypted.

⚠️ Never reuse the same (key, nonce) pair for two different plaintexts same rule as raw ChaCha20.

| Method | Signature | Key size | Nonce size | Tag size | Description |
|---|---|---|---|---|---|
| `Encrypt` | `(plaintext: string, key: string[32], nonce: string[12], aad?: string) > ciphertext: string, tag: string[16]` | 32 bytes / 256-bit | 12 bytes / 96-bit | 16 bytes / 128-bit | |
| `Decrypt` | `(ciphertext: string, tag: string[16], key: string[32], nonce: string[12], aad?: string) > plaintext?: string, error?: string` | 32 bytes | 12 bytes | 16 bytes | Returns `nil, "authentication failed"` if the tag doesn't match the ciphertext is **never** decrypted-and-returned on a failed check. |

### MCrypt.Encrypt.Cipher

Unified facade over AES/ChaCha20/XOR for picking an algorithm dynamically by name. Security rating inherits from whichever algorithm you pick see the table above (i.e. `Cipher("XOR", ...)` is exactly as insecure as `Encrypt.XOR` on its own).

| Method | Signature | Description |
|---|---|---|
| `Constructor` | `(algorithm: "AES"\|"ChaCha20"\|"XOR", ...)` | Extra arguments are forwarded to the chosen algorithm's constructor. |
| `:Encrypt` / `:Decrypt` | `(data: string, ...) > string` | Delegates to the wrapped instance. |
| `:EncryptToHex` | `(data: string, ...) > hex` | |
| `:EncryptToBase64` | `(data: string, ...) > base64` | |

```lua
local cipher = MCrypt.Encrypt.Cipher("AES", key, "CBC")
print(cipher:EncryptToHex("secret", iv))
```

---

## MCrypt.Checksum

### MCrypt.Checksum.CRC32

⚠️ **Not cryptographic.** CRC-32/ISO-HDLC (same variant used by ZIP, PNG, Ethernet). Designed to catch *accidental* corruption trivial for an adversary to forge on purpose. Do not use it as a security/integrity check against tampering.

| Method | Signature | Output size | Description |
|---|---|---|---|
| `ComputeRaw` | `(data: string) > integer` | 32-bit integer | Raw checksum. |
| `Compute` | `(data: string) > hex` | 4 bytes / 32-bit (8 hex chars) | |

### MCrypt.Checksum.Adler32

⚠️ **Not cryptographic.** Used by zlib. Same caveat as CRC32 accidental-corruption detection only.

| Method | Signature | Output size | Description |
|---|---|---|---|
| `ComputeRaw` | `(data: string) > integer` | 32-bit integer | |
| `Compute` | `(data: string) > hex` | 4 bytes / 32-bit (8 hex chars) | |

---

## MCrypt.Sign

### MCrypt.Sign.EdDSA

✅ Secure. Ed25519 (RFC 8032) recommended for player authentication (see the challenge-response pattern below) and any scenario needing tamper-evident, verifiable signatures.

| Method | Signature | Sizes | Description |
|---|---|---|---|
| `GenerateKeypair` | `(seed?: string[32 bytes]) > publicKey: string[32], privateKey: string[64]` | seed 32 bytes, public key 32 bytes / 256-bit, private key 64 bytes | `seed` is random if omitted. `privateKey` = seed \|\| public key. |
| `Sign` | `(message: string, privateKey: string[64]) > signature: string[64]` | signature 64 bytes / 512-bit | Deterministic (RFC 8032) signing the same message twice with the same key produces the same signature. |
| `Verify` | `(message: string, signature: string[64], publicKey: string[32]) > boolean` | - | |
| `NewKey` | `(seed?: string[32]) > EdDSAKey` | - | Generates a keypair and wraps it in an OOP instance. |

**`EdDSAKey` instance**

| Method | Signature | Description |
|---|---|---|
| `:Sign` | `(message: string) > signature: string[64]` | |
| `:Verify` | `(message: string, signature: string[64]) > boolean` | |

```lua
local key = MCrypt.Sign.EdDSA.NewKey()
local sig = key:Sign("Hello!")
print(key:Verify("Hello!", sig)) -- true
```

**Recommended pattern player authentication without storing passwords**: the server sends a random nonce (`Utility.Random.Bytes(32)`), the client signs it with a locally-stored private key (`Sign`) and returns the signature, the server verifies it against the player's registered public key (`Verify`). No secret is ever transmitted or stored server-side beyond a public key and the nonce is single-use, so intercepted signatures can't be replayed.

---

## The "byte string" convention

nanos world runs standard Lua (no Luau-style `buffer` type). Throughout this framework, a **byte string** means a regular Lua string where each character represents one byte (0-255) Lua strings are natively binary-safe, so this costs nothing extra. It's the direct equivalent of the `buffer` type used in Luau/Roblox reference implementations.

Use `MCrypt.Utility.Conversions` to move between byte strings, hex and numeric byte arrays depending on what you need (storage, display, network transmission...).
