/*
 * ACFP - Advanced C Fuzzing Platform
 * Report Generation Implementation
 */

#include "acfp_fuzzer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* Generate Markdown report */
int acfp_report_generate_md(acfp_crash_info_t *crash, const char *out_path) {
    if (!crash || !out_path) return -1;

    FILE *f = fopen(out_path, "w");
    if (!f) return -1;

    /* Map crash type to CWE */
    const char *cwe = acfp_cwe_map(crash->type);
    strncpy(crash->cwe_candidate, cwe, sizeof(crash->cwe_candidate) - 1);

    /* Estimate CVSS */
    crash->cvss_score = acfp_cvss_estimate(crash);

    /* Assess exploitability */
    crash->exploitability = acfp_crash_exploitability(crash);

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char date_str[64];
    strftime(date_str, sizeof(date_str), "%Y-%m-%d %H:%M:%S", tm_info);

    fprintf(f, "# Vulnerability Report: %s\n\n", crash->id);
    fprintf(f, "**Generated:** %s  \n", date_str);
    fprintf(f, "**Status:** %s\n\n", acfp_state_str(crash->state));

    fprintf(f, "## Summary\n\n");
    fprintf(f, "| Field | Value |\n");
    fprintf(f, "|-------|-------|\n");
    fprintf(f, "| **Crash ID** | `%s` |\n", crash->id);
    fprintf(f, "| **Crash Hash** | `%s` |\n", crash->crash_hash);
    fprintf(f, "| **Type** | %s |\n", acfp_crash_type_str(crash->type));
    fprintf(f, "| **Severity** | **%s** |\n", acfp_severity_str(crash->severity));
    fprintf(f, "| **CWE Candidate** | %s |\n", crash->cwe_candidate);
    fprintf(f, "| **CVSS v3.1 Estimate** | %.1f |\n", crash->cvss_score);
    fprintf(f, "| **Exploitability** | %s |\n", acfp_exploitability_str(crash->exploitability));
    fprintf(f, "| **Target** | `%s` |\n", crash->target_name);
    fprintf(f, "| **First Seen** | %lu |\n", crash->first_seen);
    fprintf(f, "| **Occurrences** | %lu |\n\n", crash->occurrence_count);

    fprintf(f, "## Technical Details\n\n");
    
    if (crash->affected_function[0]) {
        fprintf(f, "### Affected Function\n\n");
        fprintf(f, "```\n%s\n```\n\n", crash->affected_function);
    }

    if (crash->affected_file[0] && crash->affected_line > 0) {
        fprintf(f, "### Location\n\n");
        fprintf(f, "- **File:** `%s`\n", crash->affected_file);
        fprintf(f, "- **Line:** %d\n\n", crash->affected_line);
    }

    if (crash->sanitizer_output[0]) {
        fprintf(f, "### Sanitizer Output\n\n");
        fprintf(f, "```\n%s\n```\n\n", crash->sanitizer_output);
    }

    if (crash->stack_trace[0]) {
        fprintf(f, "### Stack Trace\n\n");
        fprintf(f, "```\n%s\n```\n\n", crash->stack_trace);
    }

    fprintf(f, "## Exploitability Assessment\n\n");
    fprintf(f, "**Classification:** %s\n\n", acfp_exploitability_str(crash->exploitability));
    
    switch (crash->exploitability) {
        case EXPLOIT_EXPLOITABLE:
            fprintf(f, "This vulnerability appears to be potentially exploitable based on the crash characteristics.\n");
            fprintf(f, "The crash type (%s) typically indicates memory corruption that could be leveraged for arbitrary code execution.\n\n", acfp_crash_type_str(crash->type));
            break;
        case EXPLOIT_PROBABLY_EXPLOITABLE:
            fprintf(f, "This vulnerability is likely exploitable under certain conditions.\n");
            fprintf(f, "Further analysis is recommended to determine the exact exploitation potential.\n\n");
            break;
        case EXPLOIT_DOS_ONLY:
            fprintf(f, "This vulnerability appears to be limited to denial-of-service impact.\n");
            fprintf(f, "While it causes a crash, exploitation for code execution is unlikely.\n\n");
            break;
        default:
            fprintf(f, "Additional manual analysis is required to determine exploitability.\n\n");
            break;
    }

    fprintf(f, "## Reproduction Steps\n\n");
    fprintf(f, "1. Build the target with sanitizers enabled:\n");
    fprintf(f, "   ```bash\n");
    fprintf(f, "   clang -fsanitize=address,undefined -g -o target target.c\n");
    fprintf(f, "   ```\n\n");
    fprintf(f, "2. Run the target with the provided reproducer:\n");
    fprintf(f, "   ```bash\n");
    fprintf(f, "   ./target %s\n", crash->reproducer_path);
    fprintf(f, "   ```\n\n");
    fprintf(f, "3. Observe the crash with sanitizer output as shown above.\n\n");

    fprintf(f, "## Impact Statement\n\n");
    fprintf(f, "This vulnerability affects `%s` and may result in:\n", crash->target_name);
    
    switch (crash->type) {
        case CRASH_HEAP_OVERFLOW:
        case CRASH_STACK_OVERFLOW:
            fprintf(f, "- Arbitrary code execution through heap/stack corruption\n");
            fprintf(f, "- Information disclosure through memory leakage\n");
            fprintf(f, "- Denial of service through application crash\n");
            break;
        case CRASH_USE_AFTER_FREE:
        case CRASH_DOUBLE_FREE:
            fprintf(f, "- Use-after-free exploitation leading to code execution\n");
            fprintf(f, "- Heap metadata corruption\n");
            fprintf(f, "- Denial of service\n");
            break;
        case CRASH_OUT_OF_BOUNDS_READ:
            fprintf(f, "- Information disclosure through out-of-bounds memory read\n");
            fprintf(f, "- Potential bypass of security controls\n");
            fprintf(f, "- Denial of service\n");
            break;
        default:
            fprintf(f, "- Application crash and denial of service\n");
            fprintf(f, "- Potential for further exploitation depending on context\n");
            break;
    }
    fprintf(f, "\n");

    fprintf(f, "## Suggested Patch Guidance\n\n");
    fprintf(f, "### Immediate Mitigations\n\n");
    fprintf(f, "1. Enable compiler sanitizers during development and testing\n");
    fprintf(f, "2. Implement input validation at trust boundaries\n");
    fprintf(f, "3. Add bounds checking for all array/buffer operations\n\n");

    fprintf(f, "### Long-term Fixes\n\n");
    switch (crash->type) {
        case CRASH_HEAP_OVERFLOW:
        case CRASH_STACK_OVERFLOW:
            fprintf(f, "- Replace unsafe functions (strcpy, sprintf) with bounded alternatives (strncpy, snprintf)\n");
            fprintf(f, "- Validate input lengths before copying to fixed-size buffers\n");
            fprintf(f, "- Consider using safe string libraries\n");
            break;
        case CRASH_USE_AFTER_FREE:
            fprintf(f, "- Set pointers to NULL after freeing\n");
            fprintf(f, "- Implement proper ownership semantics for dynamically allocated memory\n");
            fprintf(f, "- Consider using smart pointers or reference counting\n");
            break;
        case CRASH_INTEGER_OVERFLOW:
            fprintf(f, "- Check for overflow before arithmetic operations\n");
            fprintf(f, "- Use safe integer arithmetic libraries\n");
            fprintf(f, "- Validate input ranges\n");
            break;
        default:
            fprintf(f, "- Review code at crash location for proper input validation\n");
            fprintf(f, "- Add assertions for invariant checking\n");
            fprintf(f, "- Implement comprehensive error handling\n");
            break;
    }
    fprintf(f, "\n");

    fprintf(f, "## Disclosure Timeline (Recommended)\n\n");
    fprintf(f, "| Date | Action |\n");
    fprintf(f, "|------|--------|\n");
    fprintf(f, "| Day 0 | Vulnerability discovered |\n");
    fprintf(f, "| Day 1 | Vendor notification sent |\n");
    fprintf(f, "| Day 7-30 | Vendor response window |\n");
    fprintf(f, "| Day 30-90 | Coordinated patch development |\n");
    fprintf(f, "| Day 90 | Public disclosure (if no response) |\n\n");

    fprintf(f, "## CVE Request Draft\n\n");
    fprintf(f, "```\n");
    fprintf(f, "Requester: [Your Name/Organization]\n");
    fprintf(f, "Product: [Target Product Name]\n");
    fprintf(f, "Version: [Affected Version(s)]\n");
    fprintf(f, "Vulnerability Type: %s\n", acfp_crash_type_str(crash->type));
    fprintf(f, "CWE: %s\n", crash->cwe_candidate);
    fprintf(f, "CVSS Score: %.1f\n", crash->cvss_score);
    fprintf(f, "Description: A %s vulnerability exists in %s that allows ", 
            acfp_crash_type_str(crash->type), crash->target_name);
    switch (crash->exploitability) {
        case EXPLOIT_EXPLOITABLE:
        case EXPLOIT_PROBABLY_EXPLOITABLE:
            fprintf(f, "a remote attacker to potentially execute arbitrary code.\n");
            break;
        case EXPLOIT_DOS_ONLY:
            fprintf(f, "an attacker to cause a denial of service condition.\n");
            break;
        default:
            fprintf(f, "an attacker to cause unexpected behavior.\n");
            break;
    }
    fprintf(f, "The vulnerability is triggered when processing malformed input.\n");
    fprintf(f, "Proof of Concept: Available upon request.\n");
    fprintf(f, "```\n\n");

    fprintf(f, "## References\n\n");
    fprintf(f, "- [CWE-%s](https://cwe.mitre.org/data/definitions/%s.html)\n", 
             strchr(crash->cwe_candidate, '-') + 1, strchr(crash->cwe_candidate, '-') + 1);
    fprintf(f, "- [CVSS v3.1 Calculator](https://www.first.org/cvss/calculator/3.1)\n");
    fprintf(f, "- [Responsible Disclosure Guidelines](https://www.iso.org/standard/45170.html)\n\n");

    fprintf(f, "---\n\n");
    fprintf(f, "*This report was generated by ACFP (Advanced C Fuzzing Platform) v%s.*\n", ACFP_VERSION_STRING);
    fprintf(f, "*For authorized security research and responsible disclosure only.*\n");

    fclose(f);

    printf("[*] Generated Markdown report: %s\n", out_path);
    return 0;
}

/* Generate JSON report */
int acfp_report_generate_json(acfp_crash_info_t *crash, const char *out_path) {
    if (!crash || !out_path) return -1;

    FILE *f = fopen(out_path, "w");
    if (!f) return -1;

    const char *cwe = acfp_cwe_map(crash->type);
    strncpy(crash->cwe_candidate, cwe, sizeof(crash->cwe_candidate) - 1);
    crash->cvss_score = acfp_cvss_estimate(crash);
    crash->exploitability = acfp_crash_exploitability(crash);

    fprintf(f, "{\n");
    fprintf(f, "  \"id\": \"%s\",\n", crash->id);
    fprintf(f, "  \"crash_hash\": \"%s\",\n", crash->crash_hash);
    fprintf(f, "  \"type\": \"%s\",\n", acfp_crash_type_str(crash->type));
    fprintf(f, "  \"severity\": \"%s\",\n", acfp_severity_str(crash->severity));
    fprintf(f, "  \"cwe\": \"%s\",\n", crash->cwe_candidate);
    fprintf(f, "  \"cvss_score\": %.1f,\n", crash->cvss_score);
    fprintf(f, "  \"exploitability\": \"%s\",\n", acfp_exploitability_str(crash->exploitability));
    fprintf(f, "  \"target\": \"%s\",\n", crash->target_name);
    fprintf(f, "  \"first_seen\": %lu,\n", crash->first_seen);
    fprintf(f, "  \"last_seen\": %lu,\n", crash->last_seen);
    fprintf(f, "  \"occurrences\": %lu,\n", crash->occurrence_count);
    fprintf(f, "  \"state\": \"%s\",\n", acfp_state_str(crash->state));
    fprintf(f, "  \"reproducer_path\": \"%s\",\n", crash->reproducer_path);
    fprintf(f, "  \"cwe_description\": \"%s\",\n", acfp_cwe_map(crash->type));
    fprintf(f, "  \"sanitizer_output\": ");
    
    /* Escape JSON string */
    fputc('"', f);
    for (const char *p = crash->sanitizer_output; *p && p - crash->sanitizer_output < 1000; p++) {
        if (*p == '"') fprintf(f, "\\\"");
        else if (*p == '\\') fprintf(f, "\\\\");
        else if (*p == '\n') fprintf(f, "\\n");
        else if (*p == '\r') fprintf(f, "\\r");
        else if (*p == '\t') fprintf(f, "\\t");
        else fputc(*p, f);
    }
    fprintf(f, "\"\n");
    
    fprintf(f, "}\n");

    fclose(f);
    printf("[*] Generated JSON report: %s\n", out_path);
    return 0;
}

/* Generate SARIF report (placeholder) */
int acfp_report_generate_sarif(acfp_crash_info_t *crash, const char *out_path) {
    if (!crash || !out_path) return -1;

    FILE *f = fopen(out_path, "w");
    if (!f) return -1;

    fprintf(f, "{\n");
    fprintf(f, "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n");
    fprintf(f, "  \"version\": \"2.1.0\",\n");
    fprintf(f, "  \"runs\": [{\n");
    fprintf(f, "    \"tool\": {\n");
    fprintf(f, "      \"driver\": {\n");
    fprintf(f, "        \"name\": \"ACFP\",\n");
    fprintf(f, "        \"version\": \"%s\",\n", ACFP_VERSION_STRING);
    fprintf(f, "        \"informationUri\": \"https://github.com/acfp\"\n");
    fprintf(f, "      }\n");
    fprintf(f, "    },\n");
    fprintf(f, "    \"results\": [{\n");
    fprintf(f, "      \"ruleId\": \"%s\",\n", acfp_cwe_map(crash->type));
    fprintf(f, "      \"level\": \"%s\",\n", 
             crash->severity >= SEVERITY_HIGH ? "error" : 
             crash->severity >= SEVERITY_MEDIUM ? "warning" : "note");
    fprintf(f, "      \"message\": {\n");
    fprintf(f, "        \"text\": \"%s vulnerability detected in %s\"\n", 
             acfp_crash_type_str(crash->type), crash->target_name);
    fprintf(f, "      },\n");
    fprintf(f, "      \"locations\": [{\n");
    fprintf(f, "        \"physicalLocation\": {\n");
    fprintf(f, "          \"artifactLocation\": {\n");
    fprintf(f, "            \"uri\": \"%s\"\n", crash->reproducer_path);
    fprintf(f, "          }\n");
    fprintf(f, "        }\n");
    fprintf(f, "      }]\n");
    fprintf(f, "    }]\n");
    fprintf(f, "  }]\n");
    fprintf(f, "}\n");

    fclose(f);
    printf("[*] Generated SARIF report: %s\n", out_path);
    return 0;
}

/* Generate CVE draft document */
int acfp_report_generate_cve_draft(acfp_crash_info_t *crash, const char *out_path) {
    if (!crash || !out_path) return -1;

    FILE *f = fopen(out_path, "w");
    if (!f) return -1;

    const char *cwe = acfp_cwe_map(crash->type);
    strncpy(crash->cwe_candidate, cwe, sizeof(crash->cwe_candidate) - 1);
    crash->cvss_score = acfp_cvss_estimate(crash);

    fprintf(f, "CVE REQUEST DRAFT\n");
    fprintf(f, "=================\n\n");
    
    fprintf(f, "REQUESTER INFORMATION\n");
    fprintf(f, "---------------------\n");
    fprintf(f, "Name: [Researcher Name]\n");
    fprintf(f, "Organization: [Organization]\n");
    fprintf(f, "Email: [Contact Email]\n\n");

    fprintf(f, "VULNERABILITY DETAILS\n");
    fprintf(f, "--------------------\n");
    fprintf(f, "Product Name: [Product Name]\n");
    fprintf(f, "Vendor: [Vendor Name]\n");
    fprintf(f, "Affected Versions: [Version Range]\n");
    fprintf(f, "Fixed Version: [If known]\n\n");

    fprintf(f, "TECHNICAL DETAILS\n");
    fprintf(f, "-----------------\n");
    fprintf(f, "Vulnerability Type: %s\n", acfp_crash_type_str(crash->type));
    fprintf(f, "CWE Classification: %s\n", crash->cwe_candidate);
    fprintf(f, "CVSS v3.1 Base Score: %.1f\n\n", crash->cvss_score);

    fprintf(f, "DESCRIPTION\n");
    fprintf(f, "-----------\n");
    fprintf(f, "A %s vulnerability has been identified in [Product Name]. ", acfp_crash_type_str(crash->type));
    fprintf(f, "This vulnerability allows ");
    
    switch (crash->exploitability) {
        case EXPLOIT_EXPLOITABLE:
        case EXPLOIT_PROBABLY_EXPLOITABLE:
            fprintf(f, "a potentially unauthenticated attacker to execute arbitrary code ");
            break;
        case EXPLOIT_DOS_ONLY:
            fprintf(f, "an attacker to cause a denial of service condition ");
            break;
        default:
            fprintf(f, "an attacker to trigger unexpected behavior ");
            break;
    }
    
    fprintf(f, "by providing specially crafted input to the affected component.\n\n");

    fprintf(f, "IMPACT\n");
    fprintf(f, "------\n");
    fprintf(f, "Successful exploitation of this vulnerability could result in:\n");
    switch (crash->severity) {
        case SEVERITY_CRITICAL:
            fprintf(f, "- Complete system compromise\n");
            fprintf(f, "- Arbitrary code execution with elevated privileges\n");
            break;
        case SEVERITY_HIGH:
            fprintf(f, "- Partial system compromise\n");
            fprintf(f, "- Information disclosure\n");
            break;
        case SEVERITY_MEDIUM:
            fprintf(f, "- Limited information disclosure\n");
            fprintf(f, "- Service disruption\n");
            break;
        default:
            fprintf(f, "- Minor service disruption\n");
            break;
    }
    fprintf(f, "- Denial of service\n\n");

    fprintf(f, "REPRODUCTION\n");
    fprintf(f, "------------\n");
    fprintf(f, "A proof-of-concept reproducer is available and can be provided securely.\n");
    fprintf(f, "Reproducer Hash: %s\n\n", crash->crash_hash);

    fprintf(f, "TIMELINE\n");
    fprintf(f, "--------\n");
    fprintf(f, "- Discovery Date: %lu (Unix timestamp)\n", crash->first_seen);
    fprintf(f, "- Vendor Notification: [Date]\n");
    fprintf(f, "- Expected Disclosure: [90 days from notification]\n\n");

    fprintf(f, "REFERENCES\n");
    fprintf(f, "----------\n");
    fprintf(f, "- CWE-%s: %s\n", strchr(cwe, '-') + 1, cwe);
    fprintf(f, "- CVSS Calculator: https://www.first.org/cvss/calculator/3.1\n\n");

    fprintf(f, "DISCLOSURE POLICY\n");
    fprintf(f, "-----------------\n");
    fprintf(f, "This vulnerability is being disclosed in accordance with responsible disclosure principles.\n");
    fprintf(f, "We request a 90-day coordination period before public disclosure.\n\n");

    fprintf(f, "---\n");
    fprintf(f, "Generated by ACFP v%s\n", ACFP_VERSION_STRING);

    fclose(f);
    printf("[*] Generated CVE draft: %s\n", out_path);
    return 0;
}
