# Building for Nano S

This port targets the original Nano S running firmware 2.1.0.

Use the development environment described in the repository's
[build instructions](../README.md#building). The Nano S SDK revision is
`93fa69b170dd819c6b93d5cf49dd21acee51ffd0` (`lns-2.1.0-v22.1`).

## SDK preparation

The legacy SDK shares its receive buffer between transports. The Nano S port
requires additional ownership hooks so a pending review retains its request.
Prepare a separate copy of the pinned SDK from the repository root:

```sh
git clone https://github.com/LedgerHQ/ledger-secure-sdk.git .cache/sdk-source
git -C .cache/sdk-source checkout 93fa69b170dd819c6b93d5cf49dd21acee51ffd0
python3 compat/prepare_sdk.py .cache/sdk-source .cache/nanos-sdk
```

The preparation script uses the Python standard library, checks the SDK revision
and source hashes, and applies the transport hooks to `.cache/nanos-sdk`.

## Build

Build with the prepared SDK using the project's usual `make` command:

```sh
make BOLOS_SDK="$PWD/.cache/nanos-sdk" DEBUG=0
```

Use the compiler configuration supplied by the development environment. For the
tested standalone Linux toolchain, the explicit settings were:

```sh
make BOLOS_SDK="$PWD/.cache/nanos-sdk" DEBUG=0 \
  CLANGPATH=/usr/bin/ GCCPATH=/usr/bin/ SYSROOT=/usr/lib/arm-none-eabi \
  SDK_NAME=ledger-secure-sdk SDK_VERSION=lns-2.1.0-v22.1 \
  SDK_HASH=93fa69b170dd819c6b93d5cf49dd21acee51ffd0
```

These settings were tested with Clang 18.1.3 and ARM GCC 13.2.1. The build
produces `bin/app.elf`, `bin/app.hex` and `bin/app.apdu`, with a 46 KiB app
allocation. Use the existing [test instructions](../tests/README.md) for the
project's test workflows.
