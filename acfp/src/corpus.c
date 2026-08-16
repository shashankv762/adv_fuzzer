/*
 * ACFP - Advanced C Fuzzing Platform
 * Corpus Management Implementation
 */

#include "acfp_fuzzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

/* Create new corpus */
acfp_corpus_t *acfp_corpus_create(size_t initial_capacity) {
    acfp_corpus_t *corpus = calloc(1, sizeof(acfp_corpus_t));
    if (!corpus) return NULL;

    corpus->capacity = initial_capacity > 0 ? initial_capacity : 100;
    corpus->inputs = calloc(corpus->capacity, sizeof(acfp_input_t *));
    if (!corpus->inputs) {
        free(corpus);
        return NULL;
    }

    corpus->count = 0;
    corpus->total_execs = 0;
    corpus->current_interesting = 0;

    return corpus;
}

/* Destroy corpus and free all inputs */
void acfp_corpus_destroy(acfp_corpus_t *corpus) {
    if (!corpus) return;

    for (size_t i = 0; i < corpus->count; i++) {
        if (corpus->inputs[i]) {
            acfp_input_destroy(corpus->inputs[i]);
        }
    }

    free(corpus->inputs);
    free(corpus);
}

/* Load corpus from directory */
int acfp_corpus_load(acfp_corpus_t *corpus, const char *dir) {
    if (!corpus || !dir) return -1;

    DIR *d = opendir(dir);
    if (!d) {
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        /* Build full path */
        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);

        /* Check if it's a regular file */
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) continue;

        /* Create input from file */
        acfp_input_t *input = acfp_input_create(st.st_size);
        if (!input) continue;

        if (acfp_input_load(input, path) == 0) {
            input->filename = acfp_strdup(entry->d_name);
            acfp_corpus_add(corpus, input);
        } else {
            acfp_input_destroy(input);
        }
    }

    closedir(d);
    printf("[*] Loaded %zu inputs from %s\n", corpus->count, dir);
    return 0;
}

/* Save corpus to directory */
int acfp_corpus_save(acfp_corpus_t *corpus, const char *dir) {
    if (!corpus || !dir) return -1;

    if (acfp_mkdir_p(dir) != 0) {
        return -1;
    }

    for (size_t i = 0; i < corpus->count; i++) {
        acfp_input_t *input = corpus->inputs[i];
        if (!input || !input->filename) continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/%s", dir, input->filename);

        acfp_input_save(input, path);
    }

    return 0;
}

/* Add input to corpus */
int acfp_corpus_add(acfp_corpus_t *corpus, acfp_input_t *input) {
    if (!corpus || !input) return -1;

    /* Expand if needed */
    if (corpus->count >= corpus->capacity) {
        size_t new_cap = corpus->capacity * 2;
        acfp_input_t **new_inputs = realloc(corpus->inputs, 
                                             new_cap * sizeof(acfp_input_t *));
        if (!new_inputs) return -1;

        corpus->inputs = new_inputs;
        corpus->capacity = new_cap;
    }

    corpus->inputs[corpus->count++] = input;
    
    if (input->interesting) {
        corpus->current_interesting++;
    }

    return 0;
}

/* Minimize corpus by removing redundant inputs */
int acfp_corpus_minimize(acfp_corpus_t *corpus) {
    if (!corpus || corpus->count <= 1) return 0;

    /* Simple minimization: keep only interesting inputs */
    size_t write_idx = 0;
    
    for (size_t i = 0; i < corpus->count; i++) {
        acfp_input_t *input = corpus->inputs[i];
        
        if (input && input->interesting) {
            corpus->inputs[write_idx++] = input;
        } else if (input) {
            acfp_input_destroy(input);
        }
    }

    /* Zero out remaining pointers */
    for (size_t i = write_idx; i < corpus->count; i++) {
        corpus->inputs[i] = NULL;
    }

    size_t removed = corpus->count - write_idx;
    corpus->count = write_idx;
    corpus->current_interesting = write_idx;

    printf("[*] Corpus minimized: removed %zu inputs, %zu remaining\n", 
           removed, corpus->count);

    return 0;
}

/* Select random input from corpus */
acfp_input_t *acfp_corpus_select(acfp_corpus_t *corpus) {
    if (!corpus || corpus->count == 0) return NULL;

    /* Prefer interesting inputs */
    if (corpus->current_interesting > 0 && (rand() % 100) < 80) {
        /* Select from interesting inputs */
        size_t attempts = 0;
        while (attempts < 10) {
            size_t idx = rand() % corpus->count;
            if (corpus->inputs[idx] && corpus->inputs[idx]->interesting) {
                return corpus->inputs[idx];
            }
            attempts++;
        }
    }

    /* Random selection */
    size_t idx = rand() % corpus->count;
    return corpus->inputs[idx];
}

/* Create new input buffer */
acfp_input_t *acfp_input_create(size_t size) {
    acfp_input_t *input = calloc(1, sizeof(acfp_input_t));
    if (!input) return NULL;

    input->capacity = size > 0 ? size : ACFP_DEFAULT_INPUT_SIZE;
    input->data = calloc(1, input->capacity);
    if (!input->data) {
        free(input);
        return NULL;
    }

    input->size = input->capacity;
    input->exec_count = 0;
    input->interesting = false;
    input->filename = NULL;

    return input;
}

/* Destroy input buffer */
void acfp_input_destroy(acfp_input_t *input) {
    if (!input) return;

    free(input->data);
    free(input->filename);
    free(input);
}

/* Load input from file */
int acfp_input_load(acfp_input_t *input, const char *path) {
    if (!input || !path) return -1;

    uint8_t *buf = NULL;
    size_t size = 0;

    if (acfp_read_file(path, &buf, &size) != 0) {
        return -1;
    }

    /* Resize if needed */
    if (size > input->capacity) {
        uint8_t *new_data = realloc(input->data, size);
        if (!new_data) {
            free(buf);
            return -1;
        }
        input->data = new_data;
        input->capacity = size;
    }

    memcpy(input->data, buf, size);
    input->size = size;
    free(buf);

    return 0;
}

/* Save input to file */
int acfp_input_save(acfp_input_t *input, const char *path) {
    if (!input || !path || !input->data) return -1;

    return acfp_write_file(path, input->data, input->size);
}

/* Clone input buffer */
acfp_input_t *acfp_input_clone(acfp_input_t *src) {
    if (!src) return NULL;

    acfp_input_t *dst = acfp_input_create(src->size);
    if (!dst) return NULL;

    dst->size = src->size;
    memcpy(dst->data, src->data, src->size);
    dst->interesting = src->interesting;
    dst->exec_count = src->exec_count;

    return dst;
}
