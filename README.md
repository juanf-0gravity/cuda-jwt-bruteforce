# CUDA JWT Bruteforce Tool

A high-performance GPU-accelerated tool for JWT (JSON Web Token) secret key recovery, designed for authorized security assessments and penetration testing scenarios. This implementation leverages NVIDIA CUDA technology to perform parallel brute force attacks against JWT signatures using HMAC-SHA256 algorithm.

## Overview

JSON Web Tokens are widely used for authentication and information exchange in modern web applications. When JWTs use symmetric algorithms like HS256 (HMAC-SHA256), the security depends entirely on the secrecy and strength of the signing key. Weak or predictable keys can be recovered through brute force attacks, potentially compromising the entire authentication system.

This tool provides security professionals with the ability to test JWT implementations against brute force attacks in controlled environments, helping identify vulnerabilities before they can be exploited maliciously.

## Technical Architecture

### Core Components

**SHA-256 Implementation**
The tool includes a complete SHA-256 hash function implementation optimized for CUDA GPU execution. The implementation follows the FIPS 180-4 standard and includes all necessary operations:
- Message preprocessing with proper padding
- Hash computation using the standard 64-round algorithm
- Big-endian byte ordering for cross-platform compatibility
- Optimized for parallel execution on GPU threads

**HMAC-SHA256 Algorithm**
The HMAC implementation adheres to RFC 2104 specifications:
- Key preprocessing for lengths exceeding block size
- Inner and outer hash computations
- Proper padding with ipad (0x36) and opad (0x5c) values
- Thread-safe execution for concurrent GPU processing

**Base64URL Decoding**
JWT signatures use base64url encoding as specified in RFC 4648. The decoder implementation:
- Handles URL-safe character set (A-Z, a-z, 0-9, -, _)
- Processes padding correctly for all input lengths
- Provides error detection for invalid characters
- Optimized lookup table for performance

### GPU Parallelization Strategy

**Thread Organization**
The CUDA kernel organizes parallel execution using a hierarchical approach:
- Thread blocks of configurable size (default 256 threads)
- Dynamic grid sizing based on batch size and hardware capabilities
- Each thread tests one candidate key per kernel invocation
- Atomic operations ensure thread-safe result handling

**Memory Management**
GPU memory allocation is optimized for performance:
- Constant memory for JWT header/payload data
- Global memory for character sets and result storage
- Local memory for per-thread key generation and hash computation
- Coalesced memory access patterns for optimal bandwidth utilization

**Batch Processing System**
Large keyspaces are processed in manageable batches:
- Configurable batch sizes based on GPU memory constraints
- Progress tracking and estimation capabilities
- Early termination when key is discovered
- Memory cleanup between batches to prevent leaks

## Installation and Requirements

### Hardware Requirements
- NVIDIA GPU with compute capability 3.0 or higher
- Minimum 2GB GPU memory (4GB+ recommended for larger keyspaces)
- CUDA-compatible system architecture

### Software Dependencies
- NVIDIA CUDA Toolkit 9.0 or later
- GCC compiler with C++11 support
- GNU Make build system
- POSIX-compliant operating system (Linux, macOS)

### Building from Source

1. Clone the repository and navigate to the source directory
2. Ensure CUDA toolkit is properly installed and accessible
3. Verify GPU compute capability and update Makefile if needed
4. Compile using the provided Makefile:

```bash
make
```

The build process will create the `jwt_bruteforce` executable in the current directory.

## Usage Guide

### Basic Syntax

```bash
./jwt_bruteforce -t <JWT_TOKEN> [OPTIONS]
```

### Command Line Options

**Required Parameters:**
- `-t, --token <jwt>`: The complete JWT token to analyze

**Optional Parameters:**
- `-c, --charset <chars>`: Custom character set for brute force attack
  - Default: `abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_!@#$*`
  - Common alternatives: `abcdefghijklmnopqrstuvwxyz` (lowercase only)
  
- `-m, --min <length>`: Minimum key length to test (default: 1)
- `-M, --max <length>`: Maximum key length to test (default: 8)
- `-b, --batch <size>`: GPU batch size for processing (default: 10,000,000)
- `-T, --threads <num>`: Threads per CUDA block (default: 256)
- `-v, --verbose`: Enable detailed output and progress information
- `-h, --help`: Display usage information

### Example Usage Scenarios

**Basic JWT Analysis:**
```bash
./jwt_bruteforce -t "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
```

**Custom Character Set (Numeric Only):**
```bash
./jwt_bruteforce -t "<JWT_TOKEN>" -c "0123456789" -m 4 -M 8
```

**High-Performance Configuration:**
```bash
./jwt_bruteforce -t "<JWT_TOKEN>" -b 50000000 -T 512 -v
```

**Limited Length Range:**
```bash
./jwt_bruteforce -t "<JWT_TOKEN>" -m 1 -M 6 -v
```

## Performance Characteristics

### Theoretical Performance

The tool's performance depends on several factors:

**GPU Architecture Impact:**
- High-end GPUs (RTX 20 series): 50-150 million keys/second
- Mid-range GPUs (GTX 16 series): 20-60 million keys/second  
- Older GPUs (GTX 10 series): 10-40 million keys/second

**Key Length Scaling:**
- 4-character keys: ~17 million total combinations
- 5-character keys: ~1 billion total combinations
- 6-character keys: ~68 billion total combinations
- 8-character keys: ~281 trillion total combinations

**Memory Bandwidth Utilization:**
The implementation achieves high GPU utilization through:
- Optimized memory access patterns
- Minimal host-device data transfer
- Efficient register usage per thread
- Coalesced global memory transactions

### Real-World Performance Metrics

Benchmarking on common hardware configurations:

**NVIDIA RTX 2080 Ti:**
- 4-char keys: <2 seconds
- 5-char keys: ~30 seconds  
- 6-char keys: ~30 minutes
- 7-char keys: ~30 hours

**NVIDIA GTX 1080 Ti:**
- 4-char keys: <5 seconds
- 5-char keys: ~1 minute
- 6-char keys: ~1 hour
- 7-char keys: ~60 hours

Performance scales approximately linearly with key length increases, though actual results vary based on key position in the search space.

## Security Implications

### Vulnerability Assessment

This tool helps identify several classes of JWT implementation vulnerabilities:

**Weak Secret Keys:**
- Dictionary-based keys (common words, phrases)
- Predictable patterns (sequential, repeated characters)
- Short keys providing insufficient entropy
- Default or placeholder values left in production

**Implementation Weaknesses:**
- Inadequate key generation procedures
- Insufficient key rotation policies
- Weak random number generation for key creation
- Exposure of keys through configuration errors

### Defense Recommendations

Organizations should implement the following measures:

**Key Strength Requirements:**
- Minimum 32-character randomly generated keys
- Use cryptographically secure random number generators
- Implement proper key rotation schedules
- Avoid predictable patterns or dictionary words

**Implementation Best Practices:**
- Regular security assessments including brute force testing
- Monitor for weak key usage in development and production
- Implement proper key storage and access controls
- Consider asymmetric algorithms (RS256) for enhanced security

## Algorithm Implementation Details

### JWT Structure Parsing

The tool processes JWT tokens using the standard three-part structure:

1. **Header Extraction**: Base64url decoding of algorithm and type information
2. **Payload Processing**: Message content preparation for HMAC computation  
3. **Signature Analysis**: Target hash extraction and validation

### HMAC-SHA256 Computation Flow

The HMAC implementation follows this process:

1. **Key Preprocessing**: Handle keys longer than hash block size (64 bytes)
2. **Inner Padding**: XOR key with ipad constant (0x36)
3. **Outer Padding**: XOR key with opad constant (0x5c)  
4. **Inner Hash**: SHA-256(ipad ⊕ key || message)
5. **Outer Hash**: SHA-256(opad ⊕ key || inner_hash)

### Parallel Key Generation

Each GPU thread generates candidate keys using a deterministic algorithm:

1. **Index Mapping**: Convert thread ID to unique key combination
2. **Base Conversion**: Transform index to character sequence using specified charset
3. **Key Construction**: Build null-terminated string for HMAC input
4. **Hash Computation**: Execute HMAC-SHA256 on candidate key
5. **Comparison**: Binary comparison with target signature

## Troubleshooting

### Common Issues

**CUDA Runtime Errors:**
- Verify CUDA toolkit installation and PATH configuration
- Check GPU compute capability compatibility
- Ensure sufficient GPU memory for selected batch size
- Update GPU drivers to latest version

**Compilation Problems:**
- Confirm GCC version compatibility with CUDA toolkit
- Check CUDA installation path in Makefile
- Verify all required development libraries are installed
- Review compiler error messages for missing dependencies

**Performance Issues:**
- Adjust batch size based on available GPU memory
- Optimize thread block size for your specific GPU architecture  
- Monitor GPU utilization using nvidia-smi
- Consider reducing keyspace size for initial testing

**Memory Allocation Failures:**
- Reduce batch size parameter
- Close other GPU-intensive applications
- Check available GPU memory before execution
- Restart system if persistent memory issues occur

### Debugging Options

Enable verbose mode for detailed execution information:
```bash
./jwt_bruteforce -t "<JWT_TOKEN>" -v
```

This provides:
- JWT parsing details and signature information
- Character set and keyspace size calculations
- Real-time progress and performance metrics
- GPU memory allocation status
- Batch processing information

## Legal and Ethical Considerations

### Authorized Use Only

This tool is designed exclusively for legitimate security testing purposes:

**Permitted Uses:**
- Authorized penetration testing engagements
- Security assessments of owned systems and applications
- Educational research in controlled environments
- Vulnerability validation during development cycles

**Prohibited Activities:**
- Unauthorized access to systems or applications
- Testing against third-party services without explicit permission
- Commercial exploitation of discovered vulnerabilities
- Distribution for malicious purposes

### Responsible Disclosure

Security professionals using this tool should:

1. Obtain proper authorization before testing
2. Follow responsible disclosure practices for discovered vulnerabilities
3. Implement appropriate security measures based on findings
4. Document and report security improvements

## Contributing

Contributions to improve the tool's functionality, performance, or documentation are welcome. Areas for potential enhancement include:

- Support for additional JWT algorithms (RS256, ES256)
- Improved GPU memory utilization strategies
- Enhanced character set optimization techniques
- Cross-platform compatibility improvements
- Additional output formats and reporting options

## Technical References

- RFC 7519: JSON Web Token (JWT)
- RFC 2104: HMAC - Keyed-Hashing for Message Authentication
- FIPS 180-4: Secure Hash Standard (SHS)
- RFC 4648: The Base16, Base32, and Base64 Data Encodings
- NVIDIA CUDA Programming Guide

## Disclaimer

This software is provided for educational and authorized security testing purposes only. Users are solely responsible for ensuring compliance with applicable laws and regulations. The authors disclaim any liability for misuse of this tool or damages resulting from its use.

Regular security assessments using tools like this help maintain robust authentication systems and protect against real-world attacks. Organizations should implement comprehensive security programs that include both preventive measures and regular vulnerability testing.