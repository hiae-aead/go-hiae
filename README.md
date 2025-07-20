# HiAE Go Implementation

A pure Go implementation of the HiAE (High-throughput Authenticated Encryption) algorithm as specified in the IETF Internet-Draft `draft-pham-cfrg-hiae`.

## Overview

HiAE is a high-throughput authenticated encryption algorithm designed for next-generation wireless systems (6G) and high-speed data transmission applications. This implementation provides:

- **Correctness**: Passes all 10 specification test vectors
- **Security**: Constant-time operations and proper error handling
- **Performance**: Optimized state management with cycling index approach
- **Standards Compliance**: Follows RFC 5116 AEAD interface

## Features

- Pure Go implementation with no external dependencies
- Full specification compliance including all edge cases
- Comprehensive test suite with all specification test vectors
- Optimized state rotation using cycling indices
- Secure memory handling and constant-time comparisons
- Support for arbitrary message and associated data lengths

## Installation

```bash
go get github.com/hiae-aead/go-hiae
```

## Usage

### Basic Encryption/Decryption

```go
package main

import (
    "fmt"
    "github.com/hiae-aead/go-hiae"
)

func main() {
    // 32-byte key (256 bits)
    key := make([]byte, 32)
    // 16-byte nonce (128 bits)
    nonce := make([]byte, 16)
    
    message := []byte("Hello, World!")
    associatedData := []byte("metadata")
    
    // Encrypt
    ciphertext, tag, err := hiae.Encrypt(message, associatedData, key, nonce)
    if err != nil {
        panic(err)
    }
    
    // Decrypt
    plaintext, err := hiae.Decrypt(ciphertext, tag, associatedData, key, nonce)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Original:  %s\n", message)
    fmt.Printf("Decrypted: %s\n", plaintext)
}
```

### Advanced Usage

```go
// Create reusable cipher instance
cipher := hiae.NewHiAE()

// Manual initialization (for custom protocols)
cipher.init(key, nonce)

// Process associated data block by block
for _, block := range adBlocks {
    cipher.absorb(block)
}

// Encrypt message blocks
for _, block := range msgBlocks {
    ctBlock := cipher.enc(block)
    // ... handle ciphertext block
}

// Generate authentication tag
tag := cipher.finalize(adLenBits, msgLenBits)
```

## Algorithm Parameters

- **Key Length**: 32 bytes (256 bits)
- **Nonce Length**: 16 bytes (128 bits)
- **Tag Length**: 16 bytes (128 bits)
- **Block Size**: 16 bytes (128 bits, AES block size)
- **Maximum Message Length**: 2^61 - 1 bytes
- **Maximum Associated Data Length**: 2^61 - 1 bytes

## Testing

Run the complete test suite:

```bash
go test -v
```

Run benchmarks:

```bash
go test -bench=.
```

The test suite includes:
- All 10 specification test vectors
- AESL function validation
- Utility function tests
- Error condition testing
- Performance benchmarks

## Test Vectors

The implementation passes all test vectors from the specification:

1. Empty plaintext, no AD
2. Single block plaintext, no AD
3. Empty plaintext with AD
4. Rate-aligned plaintext (256 bytes)
5. Rate + 1 byte plaintext
6. Rate - 1 byte plaintext
7. Medium plaintext with AD
8. Single byte plaintext
9. Two blocks plaintext
10. All zeros plaintext

## Security Considerations

- **Nonce Reuse**: Never reuse a (key, nonce) pair for encryption
- **Constant-Time**: Authentication tag verification uses constant-time comparison
- **Memory Safety**: Sensitive data is properly zeroed after use
- **Input Validation**: All inputs are validated for correct lengths

## Implementation Details

### State Management

The HiAE state consists of 16 AES blocks (256 bytes total). The implementation uses a cycling index optimization to avoid expensive memory copies during state rotation.

### Core Components

- **AESL Function**: Single AES round without AddRoundKey (SubBytes + ShiftRows + MixColumns)
- **Update Functions**: Core state update operations for absorption, encryption, and decryption
- **Diffusion**: 32 rounds of updates for complete state mixing
- **Partial Blocks**: Special handling for non-aligned ciphertext during decryption

### Architecture Considerations

While the reference implementation prioritizes correctness and clarity, it includes optimizations that benefit all architectures:
- Efficient state rotation
- Minimal memory allocations
- Cache-friendly data access patterns

## Compliance

This implementation follows:
- HiAE specification in `draft-pham-cfrg-hiae`
- RFC 5116 AEAD interface standards
- Go cryptography best practices

## License

This implementation is provided for reference and educational purposes. See the main repository for licensing terms.

## Contributing

This implementation is part of the HiAE specification development. For issues or contributions, please refer to the main specification repository.

## References

- [HiAE Specification](https://github.com/hiae-aead/draft-pham-hiae)
- [RFC 5116: An Interface and Algorithms for Authenticated Encryption](https://tools.ietf.org/html/rfc5116)
- [FIPS 197: Advanced Encryption Standard (AES)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
