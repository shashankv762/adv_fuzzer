#ifndef MAFL_MUTATOR_H
#define MAFL_MUTATOR_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint64_t state;
} mafl_prng_t;

typedef struct {
    uint8_t *data;
    size_t len;
    size_t capacity;
} mafl_input_t;

/* PRNG functions */
void prng_seed(mafl_prng_t *prng, uint64_t seed);
uint64_t prng_next(mafl_prng_t *prng);
uint32_t prng_range(mafl_prng_t *prng, uint32_t max);

/* Input buffer functions */
void mafl_input_init(mafl_input_t *input, size_t initial_capacity);
void mafl_input_free(mafl_input_t *input);
int mafl_input_set(mafl_input_t *input, const uint8_t *data, size_t len);

/* Mutation functions */
int mafl_mutate_bit_flip(mafl_input_t *input, mafl_prng_t *prng);
int mafl_mutate_byte_flip(mafl_input_t *input, mafl_prng_t *prng);
int mafl_mutate_arith(mafl_input_t *input, mafl_prng_t *prng, int width);
int mafl_mutate_interesting(mafl_input_t *input, mafl_prng_t *prng, int width);
int mafl_mutate_havoc(mafl_input_t *input, mafl_prng_t *prng);
int mafl_mutate_splice(mafl_input_t *out, mafl_input_t *a, mafl_input_t *b, mafl_prng_t *prng);
int mafl_mutate_trim(mafl_input_t *input, size_t target_len);

#endif /* MAFL_MUTATOR_H */
