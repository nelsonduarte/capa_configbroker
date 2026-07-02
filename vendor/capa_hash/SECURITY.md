# Security

## Verifying the signature of a release

Published release tags are GPG-signed. The publisher's key:

- **Name**: Nelson Duarte (capa-language publisher)
- **Email**: nelson.duarte31@gmail.com
- **Fingerprint**:
  `6C1D 222D 491F B880 31E0  41A5 36CF B426 101A A24B`
- **Public key**: [`publisher.asc`](./publisher.asc) in this
  repository.

The full 40-character fingerprint without spaces:
`6C1D222D491FB88031E041A536CFB426101AA24B`. Use this exact
form in your `capa.toml`'s `verify_key` field (spaces and
colons are also accepted; the manifest parser normalises).

### Import the key

Out-of-band trust path (recommended): clone this repository,
inspect `publisher.asc`, then:

```bash
gpg --import publisher.asc
gpg --fingerprint nelson.duarte31@gmail.com
# Verify the printed fingerprint matches the one above.
```

Or fetch from a keyserver (less trustworthy; verify the
fingerprint independently):

```bash
gpg --recv-keys 6C1D222D491FB88031E041A536CFB426101AA24B
```

### Verify a tag manually

```bash
git clone https://github.com/nelsonduarte/capa_hash
cd capa_hash
git verify-tag v0.1.0
# Look for: "Good signature from "Nelson Duarte <...>" [ultimate]"
# and the fingerprint above.
```

### Verify automatically via `capa install`

Declare the fingerprint in your project's `capa.toml`:

```toml
[dependencies.capa_hash]
git = "https://github.com/nelsonduarte/capa_hash"
tag = "v0.1.0"
verify_key = "6C1D222D491FB88031E041A536CFB426101AA24B"
```

`capa install` runs `git verify-tag` against your keyring and
refuses to install when the signature is absent, invalid, or
from a different key. Details:
[docs/packages.md in the main Capa repo](https://github.com/nelsonduarte/capa-language/blob/main/docs/packages.md#sources-in-detail).

## Reporting a vulnerability

Use GitHub's private vulnerability reporting channel:

  https://github.com/nelsonduarte/capa_hash/security/advisories/new

Please include a reproducer if possible and allow up to 7 days
for an initial reply.
