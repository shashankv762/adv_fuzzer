/*
 * ACFP Demo Vulnerable Target
 * Contains intentional vulnerabilities for fuzzing demonstration
 * 
 * WARNING: This code contains deliberate security vulnerabilities!
 * Only use in controlled, authorized testing environments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define BUFFER_SIZE 64
#define MAX_RECORDS 100

/* Vulnerable structure */
typedef struct {
    char name[BUFFER_SIZE];
    int id;
    uint32_t flags;
} record_t;

/* VULNERABILITY 1: Stack buffer overflow via strcpy */
void vulnerable_copy(const char *input) {
    char buffer[BUFFER_SIZE];
    
    /* Dangerous: no bounds checking */
    strcpy(buffer, input);
    
    printf("Copied: %s\n", buffer);
}

/* VULNERABILITY 2: Heap buffer overflow */
void vulnerable_heap_copy(const char *input, size_t len) {
    char *buffer = malloc(BUFFER_SIZE);
    if (!buffer) return;
    
    /* Dangerous: copies more than allocated if len > BUFFER_SIZE */
    memcpy(buffer, input, len);
    
    printf("Heap copied %zu bytes\n", len);
    free(buffer);
}

/* VULNERABILITY 3: Integer overflow leading to heap overflow */
void vulnerable_alloc(uint32_t count) {
    /* Dangerous: integer overflow possible */
    size_t size = count * sizeof(uint32_t);
    
    if (size < 1000000) {  /* Check can be bypassed by overflow */
        uint32_t *arr = malloc(size);
        if (!arr) return;
        
        /* Initialize array */
        for (uint32_t i = 0; i < count; i++) {
            arr[i] = i;
        }
        
        printf("Allocated %u elements\n", count);
        free(arr);
    }
}

/* VULNERABILITY 4: Use after free */
void vulnerable_uaf(const char *input) {
    char *buffer = malloc(BUFFER_SIZE);
    if (!buffer) return;
    
    strncpy(buffer, input, BUFFER_SIZE - 1);
    buffer[BUFFER_SIZE - 1] = '\0';
    
    printf("Before free: %s\n", buffer);
    
    free(buffer);
    
    /* Dangerous: using freed memory */
    printf("After free: %s\n", buffer);  /* UAF! */
}

/* VULNERABILITY 5: Double free */
void vulnerable_double_free(int condition) {
    char *buffer = malloc(32);
    if (!buffer) return;
    
    free(buffer);
    
    if (condition > 0) {
        /* Dangerous: double free */
        free(buffer);
        printf("Double free triggered!\n");
    }
}

/* VULNERABILITY 6: Out-of-bounds read */
void vulnerable_oob_read(const char *input, int index) {
    char buffer[16] = "ABCDEFGHIJKLMNOP";
    
    /* Dangerous: no bounds check on index */
    if (index >= 0) {
        printf("Character at %d: %c\n", index, buffer[index]);  /* OOB read! */
    }
}

/* VULNERABILITY 7: Null pointer dereference */
void vulnerable_null_deref(int trigger) {
    char *ptr = NULL;
    
    if (trigger == 0x41414141) {
        ptr = malloc(32);
        if (ptr) {
            strcpy(ptr, "Safe path");
        }
    }
    
    /* Dangerous: ptr might be NULL */
    printf("Value: %s\n", ptr);  /* Null deref! */
}

/* VULNERABILITY 8: Format string vulnerability */
void vulnerable_format(const char *input) {
    /* Dangerous: user input as format string */
    printf(input);  /* Format string vuln! */
    printf("\n");
}

/* VULNERABILITY 9: Divide by zero */
void vulnerable_divide(int divisor) {
    int result = 100 / divisor;  /* Divide by zero! */
    printf("Result: %d\n", result);
}

/* VULNERABILITY 10: Signed/unsigned confusion */
void vulnerable_signed_confusion(int signed_val) {
    unsigned int unsigned_val = (unsigned int)signed_val;
    
    char buffer[100];
    
    /* If signed_val is negative, unsigned_val becomes large */
    if (signed_val < 0) {
        printf("Negative value: %d\n", signed_val);
        /* But this check uses signed comparison */
    }
    
    /* Dangerous: unsigned_val could be huge */
    if (unsigned_val < 200) {
        memset(buffer, 'A', unsigned_val);  /* Potential overflow */
    }
}

/* Process input file */
int process_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) {
        perror("Failed to open file");
        return 1;
    }
    
    /* Get file size */
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    if (file_size <= 0 || file_size > 10000) {
        printf("Invalid file size: %ld\n", file_size);
        fclose(f);
        return 1;
    }
    
    /* Read entire file */
    char *content = malloc(file_size + 1);
    if (!content) {
        fclose(f);
        return 1;
    }
    
    size_t read_size = fread(content, 1, file_size, f);
    content[read_size] = '\0';
    fclose(f);
    
    printf("Read %zu bytes from %s\n", read_size, filename);
    
    /* Parse simple format: COMMAND:DATA */
    if (read_size < 3) {
        free(content);
        return 0;
    }
    
    /* Find command separator */
    char *sep = strchr(content, ':');
    if (!sep) {
        /* No command, treat as raw data */
        vulnerable_copy(content);
        free(content);
        return 0;
    }
    
    /* Extract command */
    *sep = '\0';
    char *command = content;
    char *data = sep + 1;
    size_t data_len = read_size - (sep - content) - 1;
    
    printf("Command: %s\n", command);
    
    /* Dispatch based on command */
    if (strcmp(command, "COPY") == 0) {
        vulnerable_copy(data);
    }
    else if (strcmp(command, "HEAP") == 0) {
        vulnerable_heap_copy(data, data_len);
    }
    else if (strcmp(command, "ALLOC") == 0) {
        uint32_t count = atoi(data);
        vulnerable_alloc(count);
    }
    else if (strcmp(command, "UAF") == 0) {
        vulnerable_uaf(data);
    }
    else if (strcmp(command, "DOUBLE") == 0) {
        vulnerable_double_free(atoi(data));
    }
    else if (strcmp(command, "OOB") == 0) {
        vulnerable_oob_read(data, atoi(data));
    }
    else if (strcmp(command, "NULL") == 0) {
        vulnerable_null_deref(atoi(data));
    }
    else if (strcmp(command, "FORMAT") == 0) {
        vulnerable_format(data);
    }
    else if (strcmp(command, "DIVIDE") == 0) {
        vulnerable_divide(atoi(data));
    }
    else if (strcmp(command, "SIGNED") == 0) {
        vulnerable_signed_confusion(atoi(data));
    }
    else {
        printf("Unknown command: %s\n", command);
        vulnerable_copy(content);
    }
    
    free(content);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("ACFP Demo Vulnerable Target\n");
        printf("============================\n\n");
        printf("Usage: %s <input_file>\n\n", argv[0]);
        printf("Input file format: COMMAND:DATA\n\n");
        printf("Commands:\n");
        printf("  COPY:<text>     - Test stack buffer overflow\n");
        printf("  HEAP:<data>     - Test heap buffer overflow\n");
        printf("  ALLOC:<count>   - Test integer overflow\n");
        printf("  UAF:<text>      - Test use-after-free\n");
        printf("  DOUBLE:<cond>   - Test double free\n");
        printf("  OOB:<index>     - Test out-of-bounds read\n");
        printf("  NULL:<trigger>  - Test null dereference\n");
        printf("  FORMAT:<text>   - Test format string\n");
        printf("  DIVIDE:<div>    - Test divide by zero\n");
        printf("  SIGNED:<val>    - Test signed/unsigned confusion\n\n");
        printf("Example: echo 'COPY:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' | %s /dev/stdin\n", argv[0]);
        return 1;
    }
    
    return process_file(argv[1]);
}
