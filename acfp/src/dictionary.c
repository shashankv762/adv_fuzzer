/*
 * ACFP - Advanced C Fuzzing Platform
 * Dictionary Management Implementation
 */

#include "acfp_fuzzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Create dictionary */
acfp_dictionary_t *acfp_dict_create(void) {
    acfp_dictionary_t *dict = calloc(1, sizeof(acfp_dictionary_t));
    if (!dict) return NULL;

    dict->capacity = 100;
    dict->entries = calloc(dict->capacity, sizeof(acfp_dict_entry_t *));
    if (!dict->entries) {
        free(dict);
        return NULL;
    }

    dict->count = 0;
    return dict;
}

/* Destroy dictionary */
void acfp_dict_destroy(acfp_dictionary_t *dict) {
    if (!dict) return;

    for (size_t i = 0; i < dict->count; i++) {
        if (dict->entries[i]) {
            free(dict->entries[i]->data);
            free(dict->entries[i]);
        }
    }

    free(dict->entries);
    free(dict);
}

/* Load dictionary from file (AFL++ format) */
int acfp_dict_load(acfp_dictionary_t *dict, const char *path) {
    if (!dict || !path) return -1;

    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\n' || line[0] == '\r') continue;

        /* Parse AFL++ dictionary format: token="value" */
        char *eq = strchr(line, '=');
        if (!eq) continue;

        char *quote_start = strchr(eq, '"');
        if (!quote_start) continue;

        char *quote_end = strchr(quote_start + 1, '"');
        if (!quote_end) continue;

        /* Extract token value */
        size_t token_len = quote_end - (quote_start + 1);
        if (token_len == 0 || token_len > ACFP_MAX_DICT_ENTRY_SIZE) continue;

        uint8_t *token_data = malloc(token_len);
        if (!token_data) continue;

        memcpy(token_data, quote_start + 1, token_len);

        /* Add to dictionary */
        acfp_dict_add(dict, token_data, token_len);
        free(token_data);
    }

    fclose(f);
    printf("[*] Loaded %zu dictionary entries from %s\n", dict->count, path);
    return 0;
}

/* Add entry to dictionary */
int acfp_dict_add(acfp_dictionary_t *dict, const uint8_t *data, size_t size) {
    if (!dict || !data || size == 0) return -1;
    if (size > ACFP_MAX_DICT_ENTRY_SIZE) return -1;

    /* Expand if needed */
    if (dict->count >= dict->capacity) {
        size_t new_cap = dict->capacity * 2;
        acfp_dict_entry_t **new_entries = realloc(dict->entries,
                                                   new_cap * sizeof(acfp_dict_entry_t *));
        if (!new_entries) return -1;

        dict->entries = new_entries;
        dict->capacity = new_cap;
    }

    /* Create new entry */
    acfp_dict_entry_t *entry = calloc(1, sizeof(acfp_dict_entry_t));
    if (!entry) return -1;

    entry->data = malloc(size);
    if (!entry->data) {
        free(entry);
        return -1;
    }

    memcpy(entry->data, data, size);
    entry->size = size;
    entry->hit_count = 0;
    entry->active = true;

    dict->entries[dict->count++] = entry;
    return 0;
}
