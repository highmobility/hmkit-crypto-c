# HMKit Crypto C

HMKIT Crypto C is the HMKit cryptographic layer implementation based on OpenSSL. It is used in various HMKit SDKs as the crypto library.

# Table of contents

* [Architecture](#features)
* [Requirements](#requirements)
* [Getting Started](#getting-started)
* [Contributing](#contributing)

## Architecture

**General**: HMKIT Crypto C is pure c cryptography layer implementation based on OpenSSL. 

**Crypto.c**: This contains the OpenSSL implementation.

**Crypto.h**: This is the library header file that is needed to conform to the HMKit Core cryptographic abstraction layer.

**commandline**: This is a test and example application for HMKit Crypto C.

## Requirements

HMKit Crypto C is based on OpenSSL 1.1.0 

## Getting Started

Get an overview by reading the security documentation [📘 browse the documentation](https://high-mobility.com/learn/documentation/security/overview/).

## Contributing

Before starting please read our contribution rules [📘 Contributing](CONTRIBUTE.md)

### Developing

For development we use [HMKit Core](https://github.com/highmobility/hmkit-core) system_test. It is a car and a phone example application with mac Bluetooth. 

1. Go to directory system_test
2. Compile tests with make
3. Run test ./systemtest

## Licence
This repository is using MIT licence. See more in the [📘 LICENCE](LICENCE.md)