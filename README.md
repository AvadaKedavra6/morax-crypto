# MCrypt

A full OOP cryptography framework for [nanos world](https://nanos.world), written in Lua and exposed globally under the `MCrypt` namespace.

> Made with <3 by Morax/Avada :)

> **Why did I write my own cryptography library?**
>
> Because apparently I enjoy suffering.
>
> MCrypt is a self-contained cryptographic toolkit designed specifically for nanos world with an OOP API, byte-string compatibility, modern primitives and enough warnings to hopefully stop you from inventing your own encryption protocol at 3 AM.

---

## Table of contents

- [Installation & architecture](#installation--architecture)
- [Security at a glance](#security-at-a-glance)
- [Before you use this](#before-you-use-this)
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
- [Validation & test vectors](#validation--test-vectors)
- [Limitations](#limitations)
- [License](#license)

---

## Installation & architecture

MCrypt is designed to live as a nanos world package:

```text
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

Once `Shared/Index.lua` has loaded, MCrypt is exposed globally as:

```lua
_G.MCrypt
```

and exported through:

```lua
Package.Export("MCrypt", MCrypt)
```

This means it can be used directly from the package's Client/Server/Shared code and by packages depending on it.

```lua
local hash = MCrypt.Hash.SHA2.SHA256("Hello World!")
print(hash)
```

### Runtime requirements

MCrypt assumes **Lua 5.4** with:

- native 64-bit integers
- native bitwise operators:
  - `&`
  - `|`
  - `~`
  - `<<`
  - `>>`
- binary-safe Lua strings

Some parts of `Utility.Random` use Lua's `os` library. Depending on your nanos world server configuration, this may require the appropriate unsafe-library setting.

---

# Security at a glance

Read this before choosing an algorithm.

Seriously.

Most cryptographic disasters happen because someone sees a function called `Encrypt()` and immediately uses it for passwords, authentication, save data, network packets, lunch and probably their taxes.

"Bits" refers to the key size unless stated otherwise.

| Module | Rating | Key size | IV / Nonce size | Output / Tag size | Notes |
|---|:---:|---|---|---|---|
| `Encrypt.AEAD` (ChaCha20-Poly1305) | ✅ **Recommended** | 32 bytes / 256-bit | 12 bytes / 96-bit | 16-byte tag | Confidentiality + integrity/authentication in one construction. Recommended default for new encryption use cases. |
| `Encrypt.AES` (CBC / CTR) | ✅ Secure, **unauthenticated** | 16 / 24 / 32 bytes | 16 bytes | - | Confidentiality only. Use an appropriate MAC construction if authentication is required, or use AEAD instead. |
| `Encrypt.ChaCha20` | ✅ Secure, **unauthenticated** | 32 bytes / 256-bit | 12 bytes / 96-bit | - | Confidentiality only. Never reuse a `(key, nonce)` pair. Prefer AEAD when authentication is required. |
| `Encrypt.XOR` | ❌ **Not secure** | Any non-empty length | - | - | Repeating-key XOR. Obfuscation only. Do not use it as encryption. |
| `Sign.EdDSA` (Ed25519) | ✅ Secure | 32-byte public / 64-byte private | - | 64-byte signature | Digital signatures. Useful for authentication, identity and integrity proofs. |
| `Hash.SHA2` / `SHA512` / `SHA3` / `BLAKE3` | ✅ Secure | - | - | Variant-dependent | General-purpose cryptographic hashes. **Not password hashes.** |
| `Hash.HMAC` / `KMAC` | ✅ Secure MAC | Variable | - | Variant-dependent | Message authentication using a shared secret. |
| `Hash.Poly1305` | ⚠️ **One-time use** | 32 bytes / 256-bit | - | 16-byte tag | Never reuse the same Poly1305 key for different messages. |
| `Hash.MD5` | ❌ **Broken** | - | - | 16 bytes / 128-bit | Legacy compatibility only. |
| `Checksum.CRC32` / `Adler32` | ⚠️ **Not cryptographic** | - | - | 4 bytes / 32-bit | Detects accidental corruption, not malicious modification. |
| `Utility.Random` | ⚠️ **Software PRNG** | - | - | - | Not an OS-backed CSPRNG. Suitable for many game-oriented uses but do not describe it as a formally cryptographically secure random source. |

---

# Before you use this

MCrypt implements cryptographic primitives.

That does **not** automatically make every system you build with those primitives secure.

For example:

```lua
AES(key, "CBC")
```

is cryptographically valid.

This:

```text
AES-CBC + hardcoded key + reused IV + no authentication
```

is still a terrible security design.

The primitive isn't the problem.

Your protocol is.

### Some important rules

- Never reuse a ChaCha20 `(key, nonce)` pair.
- Never reuse an AEAD `(key, nonce)` pair.
- Never reuse a Poly1305 one-time key.
- Never use MD5 for security.
- Never use CRC32 as an anti-cheat mechanism.
- Never use Base64 as encryption.
- Never use XOR as real encryption.
- Never store passwords using SHA-256/SHA-512/BLAKE3/etc.
- Never hardcode long-term secrets in client-side code and expect them to remain secret.
- Never invent your own cryptographic protocol unless you have a very good reason.
- Prefer authenticated encryption when you need both confidentiality and integrity.

And perhaps the most important one:

> **If you are not sure which primitive you need, you probably want `Encrypt.AEAD`.**

---

# Password storage

## ⚠️ Do not hash passwords with MCrypt's normal hash functions

None of the following are suitable password-hashing algorithms:

```text
SHA2
SHA512
SHA3
BLAKE3
MD5
```

They are intentionally fast.

That is great for hashing files.

It is terrible for passwords.

Password storage should use a deliberately expensive password-hashing / KDF algorithm such as:

- Argon2
- scrypt
- bcrypt

These are **not currently implemented by MCrypt (coming soon)**.

If you are building a player authentication system, prefer the platform's existing identity/authentication mechanisms where possible (Steam/Epic).

For custom authentication, Ed25519 challenge-response can also be used without transmitting or storing a password-equivalent secret on the server.

---

# Which algorithm should I use?

| I need to... | Use |
|---|---|
| Encrypt sensitive data with authentication | `Encrypt.AEAD` |
| Encrypt data where I specifically need AES | `Encrypt.AES` |
| Encrypt a stream and already have authentication handled separately | `Encrypt.ChaCha20` |
| Authenticate a message with a shared secret | `Hash.HMAC` or `Hash.KMAC` |
| Generate a content hash | `Hash.BLAKE3`, `Hash.SHA2`, or `Hash.SHA3` |
| Derive a purpose-specific key | `Hash.BLAKE3.DeriveKey` |
| Authenticate a player using public-key cryptography | `Sign.EdDSA` |
| Detect accidental corruption | `Checksum.CRC32` or `Checksum.Adler32` |
| Generate a nonce, token or salt | `Utility.Random.Bytes` |
| Match an old system using MD5 | `Hash.MD5` |
| Lightly obfuscate non-sensitive data | `Encrypt.XOR` |

---

# MCrypt.Class

Internal OOP engine used by stateful MCrypt modules.

It provides lightweight class creation and inheritance without requiring an external framework.

| Method | Description |
|---|---|
| `MCrypt.Class.New(name, parent?)` | Creates a class. |
| `MCrypt.Class.Is(instance, class)` | Checks whether an object belongs to a class or its inheritance chain. |
| `MCrypt.Class.GetName(obj)` | Returns the class name. |

### Example

```lua
local Animal = MCrypt.Class.New("Animal")

function Animal:Constructor(name)
    self.Name = name
end

function Animal:Speak()
    return self.Name .. " makes a sound."
end

local Dog = MCrypt.Class.New("Dog", Animal)

function Dog:Speak()
    return self.Name .. " barks."
end

local rex = Dog("Rex")

print(rex:Speak())
-- Rex barks.

print(MCrypt.Class.Is(rex, Animal))
-- true

print(MCrypt.Class.Is(rex, Dog))
-- true

print(MCrypt.Class.GetName(rex))
-- Dog
```

---

# MCrypt.Utility

## MCrypt.Utility.Conversions

Utilities for converting between:

- byte strings
- hexadecimal strings
- byte arrays

See [The "byte string" convention](#the-byte-string-convention).

| Method | Signature | Description |
|---|---|---|
| `ToHex` | `(data: string) -> hex: string` | Converts a byte string to lowercase hexadecimal. |
| `FromHex` | `(hex: string) -> data: string` | Converts hexadecimal back to a byte string. |
| `ToByteArray` | `(data: string) -> bytes: integer[]` | Converts bytes to numeric values from 0–255. |
| `FromByteArray` | `(bytes: integer[]) -> data: string` | Converts a byte array back to a byte string. |
| `ByteToHex` | `(value: integer) -> hex: string` | Converts one byte to a two-character hexadecimal value. |

### Example

```lua
local Conversions = MCrypt.Utility.Conversions
local hex = Conversions.ToHex("Hello!")

print(hex)
-- 48656c6c6f21

local back = Conversions.FromHex(hex)

print(back)
-- Hello!

local bytes = Conversions.ToByteArray("AB")

print(bytes[1], bytes[2])
-- 65  66

print(Conversions.FromByteArray(bytes))
-- AB

print(Conversions.ByteToHex(255))
-- ff
```

---

## MCrypt.Utility.Random

MCrypt's random utility provides a software PRNG designed for nanos world environments.

It is **not an OS-backed CSPRNG**.

It mixes multiple available entropy sources, but this should not be confused with a formally verified cryptographic randomness source.

Use it for things such as:

- nonces
- salts
- temporary IDs
- game tokens
- procedural randomness

Be more careful when generating long-term cryptographic key material.

| Method | Signature | Description |
|---|---|---|
| `Bytes` | `(length: integer) > data: string` | Generates random bytes. |
| `String` | `(length: integer, alphabet?: string) > string` | Generates a random string. |
| `Integer` | `(min: integer, max: integer) > integer` | Generates an inclusive random integer. |

### Example

```lua
local Random = MCrypt.Utility.Random
local nonce = Random.Bytes(12)
local sessionToken = Random.String(24)
local diceRoll = Random.Integer(1, 6)

print(diceRoll)
-- e.g. 4

print(Random.String(6, "0123456789"))
-- e.g. 042817
```

---

## MCrypt.Utility.Base64

Standard RFC 4648 Base64 encoding.

And no:

> Base64 is not encryption.

It is encoding.

Anyone can decode it.

```lua
local Base64 = MCrypt.Utility.Base64
local encoded = Base64.Encode("Hello World!")

print(encoded)
-- SGVsbG8gV29ybGQh

local decoded = Base64.Decode(encoded)

print(decoded)
-- Hello World!
```

---

# MCrypt.Hash

## MCrypt.Hash.SHA2

SHA-224 and SHA-256.

Based on FIPS 180-4.

| Method | Signature | Output |
|---|---|---|
| `SHA256` | `(message: string, salt?: string) > hex` | 32 bytes / 256-bit |
| `SHA224` | `(message: string, salt?: string) > hex` | 28 bytes / 224-bit |

If a salt is supplied, it is appended to the message before hashing.

```lua
local SHA2 = MCrypt.Hash.SHA2

print(SHA2.SHA256("Hello World!"))
print(SHA2.SHA224("Hello World!"))
print(SHA2.SHA256("Hello World!", "some-salt"))
```

Again:

> A salt does not magically turn SHA-256 into a password-hashing algorithm.

---

## MCrypt.Hash.SHA512

SHA-384 and SHA-512.

Based on FIPS 180-4.

| Method | Signature | Output |
|---|---|---|
| `SHA512` | `(message: string, salt?: string) > hex` | 64 bytes / 512-bit |
| `SHA384` | `(message: string, salt?: string) > hex` | 48 bytes / 384-bit |

```lua
local SHA512 = MCrypt.Hash.SHA512

print(SHA512.SHA512("Hello World!"))
print(SHA512.SHA384("Hello World!"))
```

---

## MCrypt.Hash.SHA3

SHA-3 and SHAKE based on Keccak-f[1600] and FIPS 202.

| Method | Signature | Output |
|---|---|---|
| `SHA3_224` | `(message: string) > hex` | 28 bytes |
| `SHA3_256` | `(message: string) > hex` | 32 bytes |
| `SHA3_384` | `(message: string) > hex` | 48 bytes |
| `SHA3_512` | `(message: string) > hex` | 64 bytes |
| `SHAKE128` | `(message: string, outputBytes: integer) > hex` | Variable |
| `SHAKE256` | `(message: string, outputBytes: integer) > hex` | Variable |

```lua
local SHA3 = MCrypt.Hash.SHA3

print(SHA3.SHA3_256("Hello World!"))
print(SHA3.SHA3_512("Hello World!"))
print(SHA3.SHAKE128("Hello World!", 16))
print(SHA3.SHAKE256("Hello World!", 64))
```

`MCrypt.Hash.SHA3.Internal` contains lower-level Keccak/cSHAKE helpers used internally by KMAC.

Those functions are internal implementation details and should not be treated as stable public API.

---

# MCrypt.Hash.BLAKE3

BLAKE3 supports:

- standard hashing
- keyed hashing
- key derivation
- streaming
- extendable output

It is also the only hash module in MCrypt designed around a persistent hasher instance.

### Instance API

```lua
local BLAKE3 = MCrypt.Hash.BLAKE3
local hash = BLAKE3()

hash:Update("Hello ")
hash:Update("World!")

print(hash:Hex())
```

`Update` is chainable:

```lua
hash:Update("Hello "):Update("World!")
```

### One-shot API

```lua
print(BLAKE3.Hash("Hello World!"))
```

### Keyed hashing

```lua
local Random = MCrypt.Utility.Random
local key = Random.Bytes(32)

print(BLAKE3.Keyed(key, "Hello World!"))
```

### Key derivation

```lua
local masterSecret = Random.Bytes(32)
local derivedKeyHex = BLAKE3.DeriveKey("MyGame.SaveDataKey.v1", masterSecret)
local derivedKey = MCrypt.Utility.Conversions.FromHex(derivedKeyHex)

print(#derivedKey)
-- 32
```

The context string should be a stable, application-specific identifier.

For example:

```text
MyGame.SaveDataKey.v1
MyGame.NetworkEncryption.v1
MyGame.PlayerAuth.v1
```

Do not just use:

```text
"key"
```

and call it a day.

---

# MCrypt.Hash.HMAC

HMAC implementation based on RFC 2104.

Use HMAC when two parties share a secret and need to authenticate a message.

| Method | Description |
|---|---|
| `Compute` | Generic HMAC construction. |
| `SHA256` | HMAC-SHA256 shortcut. |
| `SHA224` | HMAC-SHA224 shortcut. |
| `SHA512` | HMAC-SHA512 shortcut. |
| `SHA384` | HMAC-SHA384 shortcut. |

```lua
local HMAC = MCrypt.Hash.HMAC
local sharedSecret = "server-only-secret"
local payload = "player_id=42;gold=1000"
local tag = HMAC.SHA256(payload, sharedSecret)
local valid = HMAC.SHA256(payload, sharedSecret) == tag

print(valid)
-- true
```

In a real protocol, make sure the authenticated data has an unambiguous encoding.

Do not casually concatenate fields like:

```text
user .. amount .. timestamp
```

without thinking about ambiguity and canonicalization.

---

# MCrypt.Hash.KMAC

KMAC based on NIST SP 800-185.

Unlike HMAC, KMAC is built directly on the Keccak family.

```lua
local KMAC = MCrypt.Hash.KMAC

print(KMAC.KMAC128("my key", "my message"))
print(KMAC.KMAC256("my key", "my message", 32))
```

### Customization / domain separation

```lua
local inviteTag = KMAC.KMAC128("guild-secret", "invite:42", 32, "GuildInvite")
local kickTag = KMAC.KMAC128("guild-secret", "invite:42", 32, "GuildKick")

print(inviteTag ~= kickTag)
-- true
```

Same key.

Same message.

Different purpose.

Different MAC.

Crypto people call this domain separation.

Normal people call it:

> "Please don't accidentally use the same cryptographic context for everything."

---

# MCrypt.Hash.Poly1305

Poly1305 is a one-time authenticator.

Based on RFC 8439.

## ⚠️ THE IMPORTANT PART

**Never reuse a Poly1305 key for two different messages.**

Don't.

Seriously.

It breaks the security guarantees of Poly1305 and can allow attackers to recover information about the key.

```lua
local Poly1305 = MCrypt.Hash.Poly1305
local Random = MCrypt.Utility.Random
local oneTimeKey = Random.Bytes(32)
local message = "authenticated exactly once"
local tag = Poly1305.Compute(message, oneTimeKey)

print(Poly1305.Verify(message, oneTimeKey, tag))
-- true
```

For normal application-level authenticated encryption, prefer:

```lua
MCrypt.Encrypt.AEAD
```

It handles the Poly1305 construction as part of ChaCha20-Poly1305.

---

# MCrypt.Hash.MD5

## ❌ Broken for cryptographic security

MD5 exists here for compatibility.

That's it.

Use it when an external legacy system says:

> "Give me an MD5."

Do not use it because:

> "It's shorter."

Do not use it for:

- passwords
- signatures
- authentication
- security-sensitive integrity

```lua
local MD5 = MCrypt.Hash.MD5

print(MD5.Compute("Hello World!"))
-- ed076287532e86365e841e92bfc50d8
```

---

# MCrypt.Encrypt

## MCrypt.Encrypt.ChaCha20

ChaCha20 is a modern stream cipher specified in RFC 8439.

It provides **confidentiality only**.

It does not authenticate ciphertext.

### ⚠️ Never reuse `(key, nonce)`

If you encrypt two different messages with the same key and nonce, the same keystream is reused.

That's bad.

Very bad.

Use a unique nonce for every encryption under a given key.

| Method | Signature |
|---|---|
| Constructor | `(key: string[32], nonce: string[12], counter?: integer)` |
| `:Encrypt` | `(data: string) > string` |
| `:Decrypt` | `(data: string) > string` |
| `ChaCha20.Once` | `(data, key, nonce, counter?) > string` |

```lua
local ChaCha20 = MCrypt.Encrypt.ChaCha20
local Random = MCrypt.Utility.Random
local key = Random.Bytes(32)
local nonce = Random.Bytes(12)
local cipher = ChaCha20(key, nonce)
local ciphertext = cipher:Encrypt("Hello World!")
local plaintext = ChaCha20(key, nonce):Decrypt(ciphertext)

print(plaintext)
-- Hello World!
```

`Encrypt` and `Decrypt` are the same operation for a stream cipher.

---

# MCrypt.Encrypt.XOR

## ❌ This is not encryption.

MCrypt includes repeating-key XOR because sometimes you need lightweight obfuscation.

It can hide something from a casual glance.

It cannot protect a secret from someone who actually cares.

```lua
local XOR = MCrypt.Encrypt.XOR
local encrypted = XOR("my-key"):Encrypt("not actually secret")
local decrypted = XOR("my-key"):Decrypt(encrypted)

print(decrypted)
-- not actually secret
```

If the data actually matters:

```text
XOR ❌
AES  ✅
ChaCha20 ✅
AEAD ✅✅
```

---

# MCrypt.Encrypt.AES

AES-128, AES-192 and AES-256.

Based on FIPS-197.

Supported modes:

- CBC
- CTR

### ⚠️ AES itself does not authenticate your data

CBC and CTR provide confidentiality only.

If an attacker can modify your ciphertext, raw AES does not tell you that it happened.

For new designs, prefer:

```lua
MCrypt.Encrypt.AEAD
```

### Constructor

```lua
local AES = MCrypt.Encrypt.AES
local key = MCrypt.Utility.Random.Bytes(32)
local cipher = AES(key, "CBC")
```

### CBC

CBC automatically applies PKCS#7 padding.

```lua
local iv = AES.GenerateIV()
local ciphertext =cipher:EncryptCBC("Hello World!", iv)
local plaintext = cipher:DecryptCBC(ciphertext, iv)

print(plaintext)
-- Hello World!
```

### CTR

CTR does not use padding.

```lua
local nonce = AES.GenerateIV()
local ctr = AES(key, "CTR")
local encrypted = ctr:CryptCTR("Hello World!", nonce)
local decrypted = ctr:CryptCTR(encrypted, nonce)

print(decrypted)
-- Hello World!
```

CTR encryption and decryption are the same operation.

### Generic API

```lua
local cipher = AES(key, "CBC")
local encrypted = cipher:Encrypt("Hello World!", iv)
local decrypted = cipher:Decrypt(encrypted, iv)

print(decrypted)
-- Hello World!
```

---

# MCrypt.Encrypt.AEAD

## ✅ Recommended encryption primitive

MCrypt's AEAD module implements **ChaCha20-Poly1305** according to RFC 8439.

AEAD provides:

- confidentiality
- integrity
- authenticity
- optional Additional Authenticated Data (AAD)

all in one construction.

This is generally what you want when you say:

> "I need to encrypt some data and know if someone modified it."

### ⚠️ Never reuse `(key, nonce)`

Same rule as ChaCha20.

A unique nonce is required for every message encrypted with the same key.

```lua
local AEAD = MCrypt.Encrypt.AEAD
local Random = MCrypt.Utility.Random
local key = Random.Bytes(32)
local nonce = Random.Bytes(12)
local ciphertext, tag =AEAD.Encrypt("Hello World!", key, nonce)
local plaintext, err = AEAD.Decrypt(ciphertext, tag, key, nonce)

print(plaintext)
-- Hello World!
```

### Additional Authenticated Data

AAD is authenticated but not encrypted.

Useful for things such as:

- message types
- player IDs
- protocol versions
- packet headers

```lua
local aad = "player_id=42"
local ciphertext, tag = AEAD.Encrypt("sensitive payload", key, nonce, aad)
local plaintext, err = AEAD.Decrypt(ciphertext, tag, key, nonce, aad)

print(plaintext)
-- sensitive payload
```

If the ciphertext, tag, key, nonce or AAD is modified:

```lua
local plaintext, err = AEAD.Decrypt(ciphertext, tag, key, nonce, "player_id=99")

print(plaintext)
-- nil

print(err)
-- authentication failed
```

A failed authentication check does **not** return the unauthenticated plaintext.

---

# MCrypt.Encrypt.Cipher

A unified facade allowing algorithms to be selected dynamically.

Supported algorithms:

```text
AES
ChaCha20
XOR
```

The security properties are exactly those of the selected algorithm.

In other words:

```lua
Cipher("XOR", ...)
```

does not magically make XOR secure.

Nice try.

```lua
local Cipher = MCrypt.Encrypt.Cipher
local cipher = Cipher("AES", key, "CBC")
local encrypted = cipher:EncryptToHex("secret", iv)
```

---

# MCrypt.Checksum

Checksums are useful.

They are also **not cryptography**.

Do not use them to authenticate players or protect data against malicious modification.

---

## MCrypt.Checksum.CRC32

CRC-32 / ISO-HDLC.

Useful for detecting accidental corruption.

```lua
local CRC32 = MCrypt.Checksum.CRC32

print(CRC32.Compute("The quick brown fox jumps over the lazy dog"))
-- 414fa339
```

Do not use:

```lua
if CRC32.Compute(data) == expected then
    playerIsNotHacking = true
end
```

No.

Please.

---

## MCrypt.Checksum.Adler32

Adler-32 checksum commonly associated with zlib.

```lua
local Adler32 = MCrypt.Checksum.Adler32

print(Adler32.Compute("Wikipedia"))
-- 11e60398

print(Adler32.ComputeRaw("Wikipedia"))
-- 300286104
```

Again:

> Accidental corruption detection ≠ cryptographic authentication.

---

# MCrypt.Sign

## MCrypt.Sign.EdDSA

MCrypt implements **Ed25519**, following RFC 8032.

Ed25519 provides digital signatures.

It is useful for:

- player authentication
- signed tokens
- identity proofs
- save-data integrity proofs
- challenge-response authentication

### Key sizes

| Item | Size |
|---|---:|
| Seed | 32 bytes |
| Public key | 32 bytes |
| Private key | 64 bytes |
| Signature | 64 bytes |

The private key is stored as:

```text
seed || publicKey
```

### Generate a key

```lua
local EdDSA = MCrypt.Sign.EdDSA
local publicKey, privateKey = EdDSA.GenerateKeypair()
```

Or use the OOP API:

```lua
local key = EdDSA.NewKey()
local signature = key:Sign("Hello!")

print(key:Verify("Hello!", signature))
-- true
```

### Functional API

```lua
local publicKey, privateKey = EdDSA.GenerateKeypair()
local signature = EdDSA.Sign("Hello World!", privateKey)

print(EdDSA.Verify("Hello World!", signature, publicKey))
-- true

print(EdDSA.Verify("Tampered!", signature, publicKey))
-- false
```

Ed25519 signatures are deterministic:

```lua
EdDSA.Sign(message, privateKey)
```

called twice with the same key and message produces the same signature.

---

# Player authentication with Ed25519

One useful application is challenge-response authentication.

The basic idea:

1. Server generates a random challenge.
2. Server sends the challenge to the client.
3. Client signs the challenge with its private key.
4. Client sends the signature back.
5. Server verifies the signature against the registered public key.
6. The challenge is invalidated.

```lua
-- Server

local Random = MCrypt.Utility.Random
local EdDSA = MCrypt.Sign.EdDSA
local nonce = Random.Bytes(32)

-- Send nonce to the client.
-- The client signs it with its private key.
```

The client returns the signature:

```lua
local signature = EdDSA.Sign(nonce, privateKey)
```

The server verifies:

```lua
local valid = EdDSA.Verify(nonce, signature, registeredPublicKey)

if valid then
    print("Player authenticated!")
else
    print("Authentication failed.")
end
```

### Why the nonce?

Because signatures are otherwise replayable.

If an attacker captures:

```text
message
+
signature
```

and you accept that exact pair forever, they can simply send it again.

A fresh, single-use challenge prevents that particular replay pattern.

The challenge must be:

- unpredictable enough for the protocol
- associated with the authentication attempt
- single-use
- expired after a reasonable amount of time

---

# The "byte string" convention

nanos world uses standard Lua strings rather than Luau's `buffer` type.

Throughout MCrypt, a **byte string** means:

> A normal Lua string where each character represents one byte.

Lua strings are binary-safe.

For example:

```lua
local data = string.char(0x00, 0xFF, 0x42)

print(#data)
-- 3
```

This is perfectly valid MCrypt input.

Do not assume cryptographic functions operate on human-readable text.

They operate on bytes.

For example:

```lua
local key = MCrypt.Utility.Random.Bytes(32)
```

returns a 32-byte Lua string.

If you want to display or store it in a text-oriented format:

```lua
local hex = MCrypt.Utility.Conversions.ToHex(key)
```

And to convert it back:

```lua
local key = MCrypt.Utility.Conversions.FromHex(hex)
```

### Common representations

```text
Lua byte string
        ↓
    ToHex()
        ↓
Hexadecimal string
```

or:

```text
Lua byte string
        ↓
    Base64.Encode()
        ↓
Base64 string
```

Hex and Base64 are representations.

They do not provide encryption.

---

# Validation & test vectors

MCrypt includes an integration validation suite covering the major cryptographic components.

The validation suite checks APIs and known cryptographic vectors, including:

- Random API
- SHA-2
- SHA-512 / SHA-384
- SHA-3
- BLAKE3
- HMAC
- KMAC
- Poly1305
- ChaCha20
- ChaCha20-Poly1305
- AES-128
- AES-192
- AES-256
- AES-CBC
- AES-CTR
- Ed25519 / EdDSA it took me 10 hours without any break be gentle please :'(
- CRC32
- Adler32
- encoding/conversion utilities
- cross-module integration

---

# Limitations

MCrypt is a Lua cryptographic framework for nanos world.

It is **not** intended to replace mature, audited cryptographic libraries in environments where such libraries are available and appropriate.

Important limitations include:

### Randomness

`Utility.Random` is a software PRNG and should not be advertised as a hardware/OS CSPRNG.

### Password hashing

Argon2, scrypt and bcrypt are not implemented.

Do not use MCrypt's fast hashes for password storage.

### Protocol design

MCrypt provides primitives.

It does not automatically make a protocol secure.

You are still responsible for:

- key management
- nonce management
- replay protection
- authentication flow
- key rotation
- secret storage
- message framing
- canonicalization
- access control

### Client-side secrets

Anything shipped to a client should generally be considered recoverable by that client.

Do not put your server master key in client-side Lua and then be surprised when someone finds it.

---

# A sane default

If you are starting a new project and simply want to encrypt authenticated data:

```lua
local AEAD = MCrypt.Encrypt.AEAD
local Random = MCrypt.Utility.Random

local key = Random.Bytes(32)
local nonce = Random.Bytes(12)

local ciphertext, tag = AEAD.Encrypt("sensitive data", key, nonce)
local plaintext, err = AEAD.Decrypt(ciphertext, tag, key, nonce)
```

If you need signatures:

```lua
local EdDSA = MCrypt.Sign.EdDSA
local key = EdDSA.NewKey()
local signature = key:Sign("message")
assert(key:Verify("message", signature))
```

If you need a hash:

```lua
local digest = MCrypt.Hash.BLAKE3.Hash("message")
```

If you need a MAC:

```lua
local tag = MCrypt.Hash.HMAC.SHA256("message", secretKey)
```

And if you need to lightly obfuscate something that isn't secret:

```lua
local data = MCrypt.Encrypt.XOR("key"):Encrypt("not a secret")
```

---

# Final warning

Cryptography is one of those things where:

> "It works on my machine"

is not a security audit.

MCrypt is tested against known vectors and integration tests but the existence of tests does not mean that every possible protocol built on top of it is secure.

Use the high-level primitive that matches your problem.

Prefer:

```text
AEAD
```

over manually assembling:

```text
AES
+
some hash
+
some XOR
+
a timestamp
+
hope and faith
```

And please, for the love of everything that has ever been hashed:

**do not roll your own cryptographic protocol unless you absolutely know why you are doing it.**

---

Made with <3, questionable amounts of caffeine and an unhealthy relationship with bitwise operators.

Feel free to dm me on nanos discord server if you want explains, lessons on cryptography or if you want an another modules here.

**MCrypt, because `math.random()` was apparently not enough.**
