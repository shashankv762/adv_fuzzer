/*
 * ACFP - Advanced C Fuzzing Platform
 * Mutation Strategies Implementation
 */

#include "acfp_fuzzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Bit flip mutation */
int acfp_mutate_bit_flip(acfp_input_t *input) {
    if (!input || input->size == 0) return -1;

    size_t pos = rand() % input->size;
    uint8_t bit = rand() % 8;
    
    input->data[pos] ^= (1 << bit);
    return 0;
}

/* Byte flip mutation */
int acfp_mutate_byte_flip(acfp_input_t *input) {
    if (!input || input->size == 0) return -1;

    size_t pos = rand() % input->size;
    input->data[pos] = rand() % 256;
    return 0;
}

/* Arithmetic mutation (add/sub small values) */
int acfp_mutate_arithmetic(acfp_input_t *input) {
    if (!input || input->size < 2) return -1;

    /* Choose random position and width */
    size_t pos = rand() % (input->size - 1);
    int width = (rand() % 3) + 1;  /* 1, 2, or 4 bytes */
    
    int delta = (rand() % 71) - 35;  /* -35 to +35 */
    
    if (width == 1) {
        int8_t val = (int8_t)input->data[pos];
        val += delta;
        input->data[pos] = (uint8_t)val;
    } else if (width == 2 && pos + 1 < input->size) {
        int16_t val;
        memcpy(&val, &input->data[pos], 2);
        val += delta;
        memcpy(&input->data[pos], &val, 2);
    } else if (width == 4 && pos + 3 < input->size) {
        int32_t val;
        memcpy(&val, &input->data[pos], 4);
        val += delta;
        memcpy(&input->data[pos], &val, 4);
    }

    return 0;
}

/* Interesting value mutation */
int acfp_mutate_interesting(acfp_input_t *input) {
    if (!input || input->size == 0) return -1;

    size_t pos = rand() % input->size;
    int width = rand() % 3;  /* 0=8bit, 1=16bit, 2=32bit */

    if (width == 0 || pos >= input->size) {
        size_t idx = rand() % acfp_interesting_8_len;
        input->data[pos] = (uint8_t)acfp_interesting_8[idx];
    } else if (width == 1 && pos + 1 < input->size) {
        size_t idx = rand() % acfp_interesting_16_len;
        int16_t val = acfp_interesting_16[idx];
        memcpy(&input->data[pos], &val, 2);
    } else if (pos + 3 < input->size) {
        size_t idx = rand() % acfp_interesting_32_len;
        int32_t val = acfp_interesting_32[idx];
        memcpy(&input->data[pos], &val, 4);
    }

    return 0;
}

/* Block duplication mutation */
int acfp_mutate_block_dup(acfp_input_t *input) {
    if (!input || input->size == 0) return -1;

    /* Choose random block */
    size_t start = rand() % input->size;
    size_t len = (rand() % (input->size - start)) + 1;
    
    /* Limit duplication size */
    if (len > 1024) len = 1024;
    
    /* Check capacity */
    if (input->size + len > input->capacity) {
        size_t new_cap = input->capacity * 2;
        uint8_t *new_data = realloc(input->data, new_cap);
        if (!new_data) return -1;
        
        input->data = new_data;
        input->capacity = new_cap;
    }

    /* Duplicate block after itself */
    memmove(&input->data[start + len], &input->data[start], len);
    input->size += len;

    return 0;
}

/* Block deletion mutation */
int acfp_mutate_block_del(acfp_input_t *input) {
    if (!input || input->size <= 1) return -1;

    /* Choose random block to delete */
    size_t start = rand() % input->size;
    size_t len = (rand() % (input->size - start)) + 1;
    
    /* Don't delete everything */
    if (len >= input->size) len = input->size - 1;

    /* Delete block */
    memmove(&input->data[start], &input->data[start + len], input->size - start - len);
    input->size -= len;

    return 0;
}

/* Block insertion mutation */
int acfp_mutate_block_insert(acfp_input_t *input) {
    if (!input) return -1;

    /* Generate random block */
    size_t insert_len = (rand() % 64) + 1;
    
    /* Check capacity */
    if (input->size + insert_len > input->capacity) {
        size_t new_cap = input->capacity + insert_len + 256;
        uint8_t *new_data = realloc(input->data, new_cap);
        if (!new_data) return -1;
        
        input->data = new_data;
        input->capacity = new_cap;
    }

    /* Choose insertion point */
    size_t pos = rand() % (input->size + 1);

    /* Make room */
    if (pos < input->size) {
        memmove(&input->data[pos + insert_len], &input->data[pos], input->size - pos);
    }

    /* Fill with random data */
    for (size_t i = 0; i < insert_len; i++) {
        input->data[pos + i] = rand() % 256;
    }

    input->size += insert_len;
    return 0;
}

/* Splice two inputs together */
int acfp_mutate_splice(acfp_input_t *input1, acfp_input_t *input2, acfp_input_t *dst) {
    if (!input1 || !input2 || !dst) return -1;
    if (input1->size == 0 || input2->size == 0) return -1;

    /* Choose crossover points */
    size_t cross1 = rand() % input1->size;
    size_t cross2 = rand() % input2->size;

    /* Calculate resulting size */
    size_t new_size = cross1 + (input2->size - cross2);

    /* Ensure capacity */
    if (new_size > dst->capacity) {
        uint8_t *new_data = realloc(dst->data, new_size);
        if (!new_data) return -1;
        dst->data = new_data;
        dst->capacity = new_size;
    }

    /* Splice: first part from input1, second from input2 */
    memcpy(dst->data, input1->data, cross1);
    memcpy(&dst->data[cross1], &input2->data[cross2], input2->size - cross2);
    dst->size = new_size;

    return 0;
}

/* Dictionary-based mutation */
int acfp_mutate_dictionary(acfp_input_t *input, acfp_dictionary_t *dict) {
    if (!input || !dict || dict->count == 0) return -1;

    /* Select random dictionary entry */
    size_t entry_idx = rand() % dict->count;
    acfp_dict_entry_t *entry = dict->entries[entry_idx];
    
    if (!entry || !entry->active || entry->size == 0) return -1;

    /* Choose insertion/overwrite position */
    size_t pos = rand() % (input->size + 1);
    bool overwrite = (rand() % 2) == 0;

    if (overwrite && pos + entry->size <= input->size) {
        /* Overwrite existing bytes */
        memcpy(&input->data[pos], entry->data, entry->size);
    } else {
        /* Insert dictionary entry */
        if (input->size + entry->size > input->capacity) {
            size_t new_cap = input->size + entry->size + 256;
            uint8_t *new_data = realloc(input->data, new_cap);
            if (!new_data) return -1;
            input->data = new_data;
            input->capacity = new_cap;
        }

        /* Make room */
        if (pos < input->size) {
            memmove(&input->data[pos + entry->size], &input->data[pos], input->size - pos);
        }

        /* Insert */
        memcpy(&input->data[pos], entry->data, entry->size);
        input->size += entry->size;
    }

    entry->hit_count++;
    return 0;
}

/* Main mutation dispatcher */
int acfp_mutate(acfp_input_t *src, acfp_input_t *dst, acfp_mutation_ctx_t *ctx) {
    if (!src || !dst) return -1;

    /* If src != dst, clone first */
    if (src != dst) {
        acfp_input_t *cloned = acfp_input_clone(src);
        if (!cloned) return -1;
        
        /* Copy cloned data to dst */
        if (cloned->size > dst->capacity) {
            uint8_t *new_data = realloc(dst->data, cloned->size);
            if (!new_data) {
                acfp_input_destroy(cloned);
                return -1;
            }
            dst->data = new_data;
            dst->capacity = cloned->size;
        }
        
        memcpy(dst->data, cloned->data, cloned->size);
        dst->size = cloned->size;
        acfp_input_destroy(cloned);
    }

    /* Apply mutation based on strategy */
    acfp_mutation_t strategy = ctx ? ctx->strategy : (acfp_mutation_t)(rand() % MUT_LAST);

    switch (strategy) {
        case MUT_BIT_FLIP:
            return acfp_mutate_bit_flip(dst);
        case MUT_BYTE_FLIP:
            return acfp_mutate_byte_flip(dst);
        case MUT_ARITHMETIC:
            return acfp_mutate_arithmetic(dst);
        case MUT_INTERESTING_VALUE:
            return acfp_mutate_interesting(dst);
        case MUT_BLOCK_DUPLICATION:
            return acfp_mutate_block_dup(dst);
        case MUT_BLOCK_DELETION:
            return acfp_mutate_block_del(dst);
        case MUT_BLOCK_INSERTION:
            return acfp_mutate_block_insert(dst);
        case MUT_SPLICE:
            /* Need another input for splice */
            return 0;  /* Skip for now */
        case MUT_DICTIONARY_INSERT:
        case MUT_DICTIONARY_OVERWRITE:
            /* Requires dictionary - skip */
            return 0;
        case MUT_RANDOM:
        default:
            /* Random strategy */
            strategy = (acfp_mutation_t)(rand() % (MUT_BLOCK_INSERTION + 1));
            return acfp_mutate(dst, dst, &(acfp_mutation_ctx_t){.strategy = strategy});
    }

    return 0;
}
