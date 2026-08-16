/**
 * @file corpus.c
 * @brief Corpus management implementation
 * 
 * Handles seed corpus loading, corpus minimization, and input selection.
 */

#include "acfp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

/* External function from core.c */
extern uint32_t acfp_rand_range(uint32_t max);
#define rand_range(x) acfp_rand_range(x)

/**
 * @brief Initialize corpus manager
 */
int acfp_corpus_init(acfp_corpus_t *corpus, const char *base_path)
{
    if (!corpus || !base_path) return -1;
    
    memset(corpus, 0, sizeof(*corpus));
    acfp_safe_strcpy(corpus->base_path, base_path, ACFP_MAX_PATH_LEN);
    
    /* Create base directory if it doesn't exist */
    mkdir(base_path, 0755);
    
    return 0;
}

/**
 * @brief Load corpus entries from directory
 */
static int corpus_load_from_dir(acfp_corpus_t *corpus, const char *dir_path)
{
    if (!corpus || !dir_path) return -1;
    
    DIR *dir = opendir(dir_path);
    if (!dir) return -1;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue; /* Skip hidden files */
        
        if (corpus->count >= ACFP_MAX_CORPUS_ENTRIES) {
            closedir(dir);
            return -1; /* Corpus full */
        }
        
        /* Build full path */
        char full_path[ACFP_MAX_PATH_LEN];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
        
        /* Check if regular file */
        struct stat st;
        if (stat(full_path, &st) != 0 || !S_ISREG(st.st_mode)) continue;
        
        /* Read file */
        uint8_t *data = NULL;
        size_t len = 0;
        if (acfp_read_file(full_path, &data, &len) != 0) continue;
        
        /* Allocate corpus entry */
        acfp_corpus_entry_t *ce = calloc(1, sizeof(*ce));
        if (!ce) {
            free(data);
            continue;
        }
        
        acfp_safe_strcpy(ce->path, full_path, ACFP_MAX_PATH_LEN);
        ce->data = data;
        ce->len = len;
        ce->hash = acfp_hash_buffer(data, len);
        ce->discovered = time(NULL);
        ce->execs = 0;
        ce->minimized = false;
        
        corpus->entries[corpus->count++] = ce;
        corpus->total_size += len;
    }
    
    closedir(dir);
    return 0;
}

/**
 * @brief Add data to corpus
 */
int acfp_corpus_add(acfp_corpus_t *corpus, const uint8_t *data, size_t len)
{
    if (!corpus || !data || len == 0) return -1;
    if (corpus->count >= ACFP_MAX_CORPUS_ENTRIES) return -1;
    if (corpus->total_size + len > ACFP_MAX_CORPUS_SIZE) return -1;
    
    /* Check for duplicates */
    uint32_t hash = acfp_hash_buffer(data, len);
    for (size_t i = 0; i < corpus->count; i++) {
        if (corpus->entries[i]->hash == hash && 
            corpus->entries[i]->len == len &&
            memcmp(corpus->entries[i]->data, data, len) == 0) {
            return -1; /* Duplicate */
        }
    }
    
    /* Allocate entry */
    acfp_corpus_entry_t *ce = calloc(1, sizeof(*ce));
    if (!ce) return -1;
    
    ce->data = malloc(len);
    if (!ce->data) {
        free(ce);
        return -1;
    }
    
    memcpy(ce->data, data, len);
    ce->len = len;
    ce->hash = hash;
    ce->discovered = time(NULL);
    ce->execs = 0;
    ce->minimized = false;
    
    /* Generate path */
    snprintf(ce->path, ACFP_MAX_PATH_LEN, "%s/id_%06zu", 
             corpus->base_path, corpus->count);
    
    corpus->entries[corpus->count++] = ce;
    corpus->total_size += len;
    
    /* Save to disk */
    acfp_write_file(ce->path, data, len);
    
    return 0;
}

/**
 * @brief Select a corpus entry for mutation
 */
acfp_corpus_entry_t *acfp_corpus_select(acfp_corpus_t *corpus)
{
    if (!corpus || corpus->count == 0) return NULL;
    
    /* Simple random selection - can be improved with weighted selection */
    size_t idx = rand_range(corpus->count);
    return corpus->entries[idx];
}

/**
 * @brief Minimize corpus by removing redundant entries
 */
int acfp_corpus_minimize(acfp_corpus_t *corpus)
{
    if (!corpus || corpus->count <= 1) return 0;
    
    /* Mark all entries as potentially removable */
    bool *keep = calloc(corpus->count, sizeof(bool));
    if (!keep) return -1;
    
    /* Always keep the first occurrence of each unique coverage */
    /* This is a simplified version - real minimization would track coverage */
    for (size_t i = 0; i < corpus->count; i++) {
        keep[i] = true;
    }
    
    /* Sort by size (smallest first) and remove larger duplicates */
    /* Simplified: just mark larger entries with same hash for removal */
    for (size_t i = 0; i < corpus->count; i++) {
        for (size_t j = i + 1; j < corpus->count; j++) {
            if (corpus->entries[i]->hash == corpus->entries[j]->hash) {
                /* Keep smaller one */
                if (corpus->entries[i]->len <= corpus->entries[j]->len) {
                    keep[j] = false;
                } else {
                    keep[i] = false;
                }
            }
        }
    }
    
    /* Remove marked entries */
    size_t write_idx = 0;
    size_t removed = 0;
    size_t removed_size = 0;
    
    for (size_t i = 0; i < corpus->count; i++) {
        if (keep[i]) {
            if (write_idx != i) {
                corpus->entries[write_idx] = corpus->entries[i];
            }
            write_idx++;
        } else {
            /* Free removed entry */
            free(corpus->entries[i]->data);
            free(corpus->entries[i]);
            removed++;
            removed_size += corpus->entries[i]->len;
            
            /* Remove file */
            if (corpus->entries[i]->path[0]) {
                unlink(corpus->entries[i]->path);
            }
        }
    }
    
    corpus->count = write_idx;
    corpus->total_size -= removed_size;
    
    free(keep);
    return (int)removed;
}

/**
 * @brief Cleanup corpus
 */
void acfp_corpus_cleanup(acfp_corpus_t *corpus)
{
    if (!corpus) return;
    
    for (size_t i = 0; i < corpus->count; i++) {
        if (corpus->entries[i]) {
            free(corpus->entries[i]->data);
            free(corpus->entries[i]);
        }
    }
    
    memset(corpus, 0, sizeof(*corpus));
}

/**
 * @brief Load dictionary from file
 */
int acfp_dictionary_load(acfp_dictionary_t *dict, const char *path)
{
    if (!dict || !path) return -1;
    
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    
    char line[ACFP_MAX_DICT_ENTRY_LEN + 64];
    while (fgets(line, sizeof(line), f) && dict->count < ACFP_MAX_DICTIONARY_ENTRIES) {
        /* Skip comments and empty lines */
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\0') continue;
        
        /* Parse dictionary entry */
        /* Format: "token" or token */
        uint8_t *data = NULL;
        size_t len = 0;
        
        if (*p == '"') {
            /* Quoted string */
            p++;
            data = (uint8_t *)p;
            len = 0;
            while (*p && *p != '"' && *p != '\n') {
                len++;
                p++;
            }
            if (*p == '"') {
                *p = '\0';
            }
        } else {
            /* Unquoted - read until whitespace */
            data = (uint8_t *)p;
            len = 0;
            while (*p && *p != ' ' && *p != '\t' && *p != '\n') {
                len++;
                p++;
            }
            *p = '\0';
        }
        
        if (len > 0 && len < ACFP_MAX_DICT_ENTRY_LEN) {
            memcpy(dict->entries[dict->count].data, data, len);
            dict->entries[dict->count].len = len;
            dict->entries[dict->count].hit_count = 0;
            dict->count++;
        }
    }
    
    fclose(f);
    return 0;
}

/**
 * @brief Add entry to dictionary
 */
int acfp_dictionary_add(acfp_dictionary_t *dict, const uint8_t *data, size_t len)
{
    if (!dict || !data || len == 0) return -1;
    if (dict->count >= ACFP_MAX_DICTIONARY_ENTRIES) return -1;
    if (len > ACFP_MAX_DICT_ENTRY_LEN) return -1;
    
    /* Check for duplicates */
    for (size_t i = 0; i < dict->count; i++) {
        if (dict->entries[i].len == len &&
            memcmp(dict->entries[i].data, data, len) == 0) {
            return -1; /* Duplicate */
        }
    }
    
    memcpy(dict->entries[dict->count].data, data, len);
    dict->entries[dict->count].len = len;
    dict->entries[dict->count].hit_count = 0;
    dict->count++;
    
    return 0;
}

/**
 * @brief Select dictionary entry
 */
const acfp_dict_entry_t *acfp_dictionary_select(acfp_dictionary_t *dict)
{
    if (!dict || dict->count == 0) return NULL;
    
    size_t idx = rand_range(dict->count);
    return &dict->entries[idx];
}

/**
 * @brief Initialize statistics
 */
void acfp_stats_init(acfp_stats_t *stats)
{
    if (!stats) return;
    
    memset(stats, 0, sizeof(*stats));
    stats->start_time = time(NULL);
    stats->last_update = time(NULL);
    stats->running = false;
}

/**
 * @brief Update execution count
 */
void acfp_stats_update_exec(acfp_stats_t *stats)
{
    if (!stats) return;
    
    stats->total_execs++;
    stats->last_update = time(NULL);
    
    /* Calculate execs per second */
    time_t elapsed = stats->last_update - stats->start_time;
    if (elapsed > 0) {
        stats->execs_per_sec = (double)stats->total_execs / (double)elapsed;
    }
}

/**
 * @brief Update crash count
 */
void acfp_stats_update_crash(acfp_stats_t *stats)
{
    if (!stats) return;
    stats->unique_crashes++;
}

/**
 * @brief Update hang count
 */
void acfp_stats_update_hang(acfp_stats_t *stats)
{
    if (!stats) return;
    stats->unique_hangs++;
}
