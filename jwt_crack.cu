#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cuda.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32
#define MAX_KEY_LENGTH 16

// SHA-256 constants
__device__ const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

__device__ uint32_t ROTR(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

__device__ uint32_t CH(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

__device__ uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

__device__ uint32_t EP0(uint32_t x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

__device__ uint32_t EP1(uint32_t x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

__device__ uint32_t SIG0(uint32_t x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}

__device__ uint32_t SIG1(uint32_t x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

__device__ void sha256_transform(uint32_t state[8], const unsigned char block[64]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | (block[j + 3]);
    }
    
    for (; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ void sha256_init(uint32_t state[8]) {
    state[0] = 0x6a09e667; state[1] = 0xbb67ae85; state[2] = 0x3c6ef372; state[3] = 0xa54ff53a;
    state[4] = 0x510e527f; state[5] = 0x9b05688c; state[6] = 0x1f83d9ab; state[7] = 0x5be0cd19;
}

__device__ void sha256_update(uint32_t state[8], const unsigned char *data, size_t len, 
                            unsigned char *buffer, size_t *buffer_len, uint64_t *total_len) {
    size_t i;
    *total_len += len;
    
    for (i = 0; i < len; i++) {
        buffer[*buffer_len] = data[i];
        (*buffer_len)++;
        
        if (*buffer_len == 64) {
            sha256_transform(state, buffer);
            *buffer_len = 0;
        }
    }
}

__device__ void sha256_final(uint32_t state[8], unsigned char hash[32], 
                           unsigned char *buffer, size_t buffer_len, uint64_t total_len) {
    size_t i;
    
    buffer[buffer_len++] = 0x80;
    
    if (buffer_len > 56) {
        while (buffer_len < 64) {
            buffer[buffer_len++] = 0;
        }
        sha256_transform(state, buffer);
        buffer_len = 0;
    }
    
    while (buffer_len < 56) {
        buffer[buffer_len++] = 0;
    }
    
    uint64_t bit_len = total_len * 8;
    for (int i = 0; i < 8; i++) {
        buffer[63 - i] = (unsigned char)(bit_len >> (i * 8));
    }
    
    sha256_transform(state, buffer);
    
    for (i = 0; i < 8; i++) {
        hash[i * 4] = (unsigned char)(state[i] >> 24);
        hash[i * 4 + 1] = (unsigned char)(state[i] >> 16);
        hash[i * 4 + 2] = (unsigned char)(state[i] >> 8);
        hash[i * 4 + 3] = (unsigned char)state[i];
    }
}

// Improved HMAC-SHA256 implementation
__device__ void hmac_sha256(const char* key, int key_len, const char* message, int msg_len, unsigned char* output) {
    unsigned char k_ipad[64], k_opad[64];
    unsigned char tk[32];
    
    uint32_t inner_state[8], outer_state[8];
    unsigned char inner_buffer[64], outer_buffer[64];
    size_t inner_buffer_len = 0, outer_buffer_len = 0;
    uint64_t inner_total_len = 0, outer_total_len = 0;
    
    int i;
    
    // Handle key length > 64
    if (key_len > 64) {
        uint32_t temp_state[8];
        unsigned char temp_buffer[64];
        size_t temp_buffer_len = 0;
        uint64_t temp_total_len = 0;
        
        sha256_init(temp_state);
        sha256_update(temp_state, (const unsigned char*)key, key_len, temp_buffer, &temp_buffer_len, &temp_total_len);
        sha256_final(temp_state, tk, temp_buffer, temp_buffer_len, temp_total_len);
        
        key = (const char*)tk;
        key_len = 32;
    }
    
    // Create padded keys
    for (i = 0; i < 64; i++) {
        if (i < key_len) {
            k_ipad[i] = key[i] ^ 0x36;
            k_opad[i] = key[i] ^ 0x5c;
        } else {
            k_ipad[i] = 0x36;
            k_opad[i] = 0x5c;
        }
    }
    
    // Inner hash
    sha256_init(inner_state);
    sha256_update(inner_state, k_ipad, 64, inner_buffer, &inner_buffer_len, &inner_total_len);
    sha256_update(inner_state, (const unsigned char*)message, msg_len, inner_buffer, &inner_buffer_len, &inner_total_len);
    sha256_final(inner_state, output, inner_buffer, inner_buffer_len, inner_total_len);
    
    // Outer hash
    sha256_init(outer_state);
    sha256_update(outer_state, k_opad, 64, outer_buffer, &outer_buffer_len, &outer_total_len);
    sha256_update(outer_state, output, 32, outer_buffer, &outer_buffer_len, &outer_total_len);
    sha256_final(outer_state, output, outer_buffer, outer_buffer_len, outer_total_len);
}

// Character set for brute force
__device__ const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
#define CHARSET_SIZE 62

__device__ void generate_key(unsigned long long index, int length, char* key) {
    for (int i = length - 1; i >= 0; i--) {
        key[i] = charset[index % CHARSET_SIZE];
        index /= CHARSET_SIZE;
    }
    key[length] = '\0';
}

__global__ void crack_jwt_kernel(const unsigned char* target, const char* payload, int payload_len, 
                                int key_length, unsigned long long start_index, 
                                unsigned long long num_keys, int* found, char* result) {
    unsigned long long idx = blockIdx.x * blockDim.x + threadIdx.x;
    
    if (idx >= num_keys) return;
    
    char test_key[MAX_KEY_LENGTH + 1];
    unsigned char hash[32];
    
    // Generate test key
    generate_key(start_index + idx, key_length, test_key);
    
    // Compute HMAC
    hmac_sha256(test_key, key_length, payload, payload_len, hash);
    
    // Compare with target
    bool match = true;
    for (int i = 0; i < 32; i++) {
        if (hash[i] != target[i]) {
            match = false;
            break;
        }
    }
    
    if (match && atomicCAS(found, 0, 1) == 0) {
        strcpy(result, test_key);
    }
}

int main() {
    printf("JWT CUDA Cracker v1.0\n");
    printf("Basic implementation for educational purposes\n");
    
    // Placeholder - would need actual JWT parsing
    const char* jwt_payload = "example.payload";
    const char target_hash[32] = {0}; // Would be extracted from JWT
    
    char* d_result;
    char h_result[256] = {0};
    
    cudaMalloc(&d_result, 256);
    
    crack_jwt_kernel<<<256, 256>>>(target_hash, jwt_payload, strlen(jwt_payload), d_result);
    
    cudaMemcpy(h_result, d_result, 256, cudaMemcpyDeviceToHost);
    
    if (strlen(h_result) > 0) {
        printf("Found key: %s\n", h_result);
    } else {
        printf("Key not found in current range\n");
    }
    
    cudaFree(d_result);
    return 0;
}