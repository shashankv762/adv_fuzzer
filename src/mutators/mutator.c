/**
 * Mini-AFL Advanced Fuzzer - Mutation Engine
 * 
 * Implements deterministic and havoc mutation strategies compatible with AFL/AFL++.
 * All mutations are deterministic given a fixed PRNG seed for reproducibility.
 */

#include "mafl/mutator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Mutation strategy constants from AFL/AFL++ */
#define ARITH_MAX 35
#define HAVOC_BLK_SMALL     32
#define HAVOC_BLK_MEDIUM    128
#define HAVOC_BLK_LARGE     1500
#define HAVOC_BLK_XL        32768

/* Interesting values for mutation */
static const int8_t interesting_8[] = {
    INT8_MIN, -127, -126, -1, 0, 1, 16, 32, 100, 127, INT8_MAX
};

static const int16_t interesting_16[] = {
    INT16_MIN, -128, -127, -1, 0, 1, 16, 32, 100, 127, 128, 255, 256, 512, 
    1000, 1024, 4096, 32767, INT16_MAX
};

static const int32_t interesting_32[] = {
    INT32_MIN, -100663046, -322428, -127, -1, 0, 1, 16, 32, 100, 127, 128, 
    255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535, 65536, 100000, 
    1000000, 100663045, 2147483647, INT32_MAX
};

/* Simple deterministic PRNG for reproducibility */
typedef struct {
    uint64_t state;
} mafl_prng_t;

void prng_seed(mafl_prng_t *prng, uint64_t seed) {
    prng->state = seed ? seed : (uint64_t)time(NULL);
}

uint64_t prng_next(mafl_prng_t *prng) {
    /* xorshift64 */
    prng->state ^= prng->state << 13;
    prng->state ^= prng->state >> 7;
    prng->state ^= prng->state << 17;
    return prng->state;
}

uint32_t prng_range(mafl_prng_t *prng, uint32_t max) {
    return (uint32_t)(prng_next(prng) % max);
}

typedef enum {
    MUT_BIT_FLIP_1,
    MUT_BIT_FLIP_2,
    MUT_BIT_FLIP_4,
    MUT_BYTE_FLIP,
    MUT_ARITH_8,
    MUT_ARITH_16,
    MUT_ARITH_32,
    MUT_INTERESTING_8,
    MUT_INTERESTING_16,
    MUT_INTERESTING_32,
    MUT_HAVOC,
    MUT_SPLICE,
    MUT_TRIM,
    MUT_DICT_INSERT
} mafl_mutation_type_t;

typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
} mafl_input_t;

/**
 * Initialize input buffer
 */
void mafl_input_init(mafl_input_t *input, size_t initial_capacity) {
    input->capacity = initial_capacity > 0 ? initial_capacity : 256;
    input->data = malloc(input->capacity);
    input->len = 0;
    if (input->data) {
        memset(input->data, 0, input->capacity);
    }
}

/**
 * Free input buffer
 */
void mafl_input_free(mafl_input_t *input) {
    free(input->data);
    input->data = NULL;
    input->len = 0;
    input->capacity = 0;
}

/**
 * Set input data
 */
int mafl_input_set(mafl_input_t *input, const uint8_t *data, size_t len) {
    if (len > input->capacity) {
        uint8_t *new_data = realloc(input->data, len);
        if (!new_data) {
            return -1;
        }
        input->data = new_data;
        input->capacity = len;
    }
    memcpy(input->data, data, len);
    input->len = len;
    return 0;
}

/**
 * Bit flip mutation - flips a single bit at random position
 */
int mafl_mutate_bit_flip(mafl_input_t *input, mafl_prng_t *prng) {
    if (!input || !input->data || input->len == 0) {
        return -1;
    }
    
    size_t pos = prng_range(prng, input->len);
    uint8_t bit = prng_range(prng, 8);
    input->data[pos] ^= (1 << bit);
    return 0;
}

/**
 * Byte flip mutation - flips all bits in a byte
 */
int mafl_mutate_byte_flip(mafl_input_t *input, mafl_prng_t *prng) {
    if (!input || !input->data || input->len == 0) {
        return -1;
    }
    
    size_t pos = prng_range(prng, input->len);
    input->data[pos] ^= 0xFF;
    return 0;
}

/**
 * Arithmetic mutation - adds/subtracts small value
 */
int mafl_mutate_arith(mafl_input_t *input, mafl_prng_t *prng, int width) {
    if (!input || !input->data || input->len < (size_t)width) {
        return -1;
    }
    
    size_t pos = prng_range(prng, input->len - width + 1);
    int sign = prng_range(prng, 2) ? 1 : -1;
    int val = prng_range(prng, ARITH_MAX) + 1;
    
    if (width == 1) {
        input->data[pos] += sign * val;
    } else if (width == 2 && pos + 1 < input->len) {
        int16_t v;
        memcpy(&v, &input->data[pos], 2);
        v += sign * val;
        memcpy(&input->data[pos], &v, 2);
    } else if (width == 4 && pos + 3 < input->len) {
        int32_t v;
        memcpy(&v, &input->data[pos], 4);
        v += sign * val;
        memcpy(&input->data[pos], &v, 4);
    }
    return 0;
}

/**
 * Interesting value insertion
 */
int mafl_mutate_interesting(mafl_input_t *input, mafl_prng_t *prng, int width) {
    if (!input || !input->data || input->len < (size_t)width) {
        return -1;
    }
    
    size_t pos = prng_range(prng, input->len - width + 1);
    const void *val = NULL;
    size_t count = 0;
    
    if (width == 1) {
        val = interesting_8;
        count = sizeof(interesting_8) / sizeof(interesting_8[0]);
    } else if (width == 2) {
        val = interesting_16;
        count = sizeof(interesting_16) / sizeof(interesting_16[0]);
    } else if (width == 4) {
        val = interesting_32;
        count = sizeof(interesting_32) / sizeof(interesting_32[0]);
    }
    
    if (val && count > 0) {
        size_t idx = prng_range(prng, count);
        memcpy(&input->data[pos], (const uint8_t*)val + idx * width, width);
    }
    return 0;
}

/**
 * Havoc mutation - applies multiple random mutations
 */
int mafl_mutate_havoc(mafl_input_t *input, mafl_prng_t *prng) {
    if (!input || !input->data || input->len == 0) {
        return -1;
    }
    
    int num_ops = prng_range(prng, 4) + 1;
    
    for (int i = 0; i < num_ops; i++) {
        int mut_type = prng_range(prng, 5);
        switch (mut_type) {
            case 0:
                mafl_mutate_bit_flip(input, prng);
                break;
            case 1:
                mafl_mutate_byte_flip(input, prng);
                break;
            case 2:
                mafl_mutate_arith(input, prng, 1);
                break;
            case 3:
                mafl_mutate_interesting(input, prng, 1);
                break;
            default:
                /* Block deletion or insertion could be added here */
                break;
        }
    }
    return 0;
}

/**
 * Splice two inputs together
 */
int mafl_mutate_splice(mafl_input_t *out, mafl_input_t *a, mafl_input_t *b, 
                       mafl_prng_t *prng) {
    if (!out || !a || !b || !a->data || !b->data || a->len == 0 || b->len == 0) {
        return -1;
    }
    
    size_t split_a = prng_range(prng, a->len);
    size_t split_b = prng_range(prng, b->len);
    size_t new_len = split_a + (b->len - split_b);
    
    if (mafl_input_set(out, a->data, split_a) < 0) {
        return -1;
    }
    memcpy(out->data + split_a, b->data + split_b, b->len - split_b);
    out->len = new_len;
    return 0;
}

/**
 * Trim input to smaller size while preserving coverage
 */
int mafl_mutate_trim(mafl_input_t *input, size_t target_len) {
    if (!input || !input->data || input->len <= target_len) {
        return -1;
    }
    
    /* Simple prefix trim - more sophisticated trimming would check coverage */
    input->len = target_len;
    return 0;
}
