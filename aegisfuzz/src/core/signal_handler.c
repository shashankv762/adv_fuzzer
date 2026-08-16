/*
 * AegisFuzz Enterprise - Signal Handler Implementation
 * 
 * This module provides robust signal handling for crash detection.
 * It captures register state, generates stack traces, and produces
 * structured crash reports compatible with triage systems.
 *
 * Copyright (c) 2024 AegisFuzz Project. All rights reserved.
 * Licensed under the Apache License 2.0.
 */

#define _GNU_SOURCE  /* Required for REG_* constants in ucontext.h on Linux */

#include "aegis_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <execinfo.h>
#include <ucontext.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

/* Global harness pointer for signal handlers */
static aegis_harness_t *g_harness = NULL;

/* Original signal handlers for restoration */
static struct sigaction g_orig_actions[AEGIS_MAX_SIGNAL_HANDLERS];
static const int g_tracked_signals[] = {SIGSEGV, SIGILL, SIGABRT, SIGBUS, SIGFPE};

/* Forward declarations */
static void aegis_signal_handler(int signum, siginfo_t *info, void *ucontext);
static void aegis_capture_context(const ucontext_t *uc, aegis_crash_context_t *ctx);
static void aegis_generate_stack_trace(char *buffer, size_t size);
static void aegis_write_crash_report(const aegis_crash_report_t *report);

/**
 * Initialize signal handling for the harness.
 * Registers custom handlers for critical signals.
 */
aegis_status_t aegis_signal_setup(aegis_harness_t *harness)
{
    if (!harness) {
        return AEGIS_ERR_INVALID_ARG;
    }

    g_harness = harness;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = aegis_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND; /* Reset handler after first trigger */
    sigemptyset(&sa.sa_mask);

    for (size_t i = 0; i < AEGIS_ARRAY_SIZE(g_tracked_signals); i++) {
        int sig = g_tracked_signals[i];
        
        /* Save original handler */
        if (sigaction(sig, NULL, &g_orig_actions[i]) == -1) {
            AEGIS_LOG("Failed to get original handler for signal %d", sig);
            continue;
        }

        /* Install our handler */
        if (sigaction(sig, &sa, NULL) == -1) {
            AEGIS_LOG("Failed to install handler for signal %d", sig);
            return AEGIS_ERR_UNSUPPORTED;
        }
    }

    AEGIS_LOG("Signal handlers installed successfully");
    return AEGIS_OK;
}

/**
 * Restore original signal handlers.
 * Called during cleanup or before execing the target.
 */
void aegis_signal_restore(void)
{
    for (size_t i = 0; i < AEGIS_ARRAY_SIZE(g_tracked_signals); i++) {
        int sig = g_tracked_signals[i];
        sigaction(sig, &g_orig_actions[i], NULL);
    }
    g_harness = NULL;
    AEGIS_LOG("Signal handlers restored");
}

/**
 * Main signal handler - captures crash context and generates report.
 */
static void aegis_signal_handler(int signum, siginfo_t *info, void *ucontext)
{
    if (!g_harness || !g_harness->initialized) {
        /* Re-raise signal if harness not ready */
        raise(signum);
        return;
    }

    AEGIS_LOG("Caught signal %d (%s)", signum, strsignal(signum));

    /* Update statistics */
    g_harness->stats.crashes++;

    /* Capture register context */
    aegis_crash_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.signum = signum;
    
    if (info) {
        ctx.addr = info->si_addr;
    }

    if (ucontext) {
        aegis_capture_context((const ucontext_t *)ucontext, &ctx);
    }

    /* Generate stack trace */
    char stack_trace[4096];
    aegis_generate_stack_trace(stack_trace, sizeof(stack_trace));

    /* Create crash report */
    aegis_crash_report_t report;
    memset(&report, 0, sizeof(report));

    /* Generate unique ID based on context */
    aegis_crash_generate_id(&ctx, report.id, sizeof(report.id));

    /* Determine severity based on signal type */
    switch (signum) {
        case SIGSEGV:
        case SIGBUS:
            report.severity = AEGIS_SEV_CRITICAL;
            break;
        case SIGILL:
            report.severity = AEGIS_SEV_HIGH;
            break;
        case SIGABRT:
            report.severity = AEGIS_SEV_MEDIUM;
            break;
        case SIGFPE:
            report.severity = AEGIS_SEV_HIGH;
            break;
        default:
            report.severity = AEGIS_SEV_INFO;
            break;
    }

    report.context = ctx;
    memcpy(report.stack_trace, stack_trace, sizeof(report.stack_trace) - 1);
    report.stack_trace[sizeof(report.stack_trace) - 1] = '\0';
    report.input_size = g_harness->input.size;
    
    struct timeval tv;
    gettimeofday(&tv, NULL);
    report.timestamp = (uint64_t)tv.tv_sec;
    report.exec_time_us = 0; /* Would need timer integration */

    if (g_harness->config.target_name) {
        snprintf(report.target_name, sizeof(report.target_name), "%s", g_harness->config.target_name);
    }

    /* Write crash report to disk */
    aegis_write_crash_report(&report);

    /* Save crashing input */
    if (g_harness->input.data && g_harness->input.size > 0) {
        char input_path[1024];
        snprintf(input_path, sizeof(input_path), "%s/id:%s,sig:%d,size:%zu",
                 AEGIS_DIR_CRASHES, report.id, signum, g_harness->input.size);
        
        int fd = open(input_path, O_WRONLY | O_CREAT | O_EXCL, 0644);
        if (fd >= 0) {
            write(fd, g_harness->input.data, g_harness->input.size);
            close(fd);
            snprintf(report.input_path, sizeof(report.input_path), "%s", input_path);
        }
    }

    /* Call user crash callback if registered */
    if (g_harness->crash_fn) {
        g_harness->crash_fn(&report, g_harness->user_ctx);
    }

    /* Print summary to stderr for immediate visibility */
    fprintf(stderr, "\n=== AEGISFUZZ CRASH DETECTED ===\n");
    fprintf(stderr, "Signal: %d (%s)\n", signum, strsignal(signum));
    fprintf(stderr, "ID: %s\n", report.id);
    fprintf(stderr, "Severity: %d\n", report.severity);
    fprintf(stderr, "Input Size: %zu bytes\n", g_harness->input.size);
    fprintf(stderr, "Stack Trace:\n%s\n", stack_trace);
    fprintf(stderr, "================================\n\n");

    /* Exit to allow fuzzer to process the crash */
    _exit(128 + signum);
}

/**
 * Extract register values from ucontext.
 * Platform-specific implementation for x86_64 Linux.
 */
static void aegis_capture_context(const ucontext_t *uc, aegis_crash_context_t *ctx)
{
#if defined(__x86_64__)
    const mcontext_t *mc = &uc->uc_mcontext;
    
    ctx->ip = (void *)mc->gregs[REG_RIP];
    ctx->sp = (void *)mc->gregs[REG_RSP];
    ctx->bp = (void *)mc->gregs[REG_RBP];
    
    ctx->rax = mc->gregs[REG_RAX];
    ctx->rbx = mc->gregs[REG_RBX];
    ctx->rcx = mc->gregs[REG_RCX];
    ctx->rdx = mc->gregs[REG_RDX];
    ctx->rsi = mc->gregs[REG_RSI];
    ctx->rdi = mc->gregs[REG_RDI];
    ctx->r8  = mc->gregs[REG_R8];
    ctx->r9  = mc->gregs[REG_R9];
    ctx->r10 = mc->gregs[REG_R10];
    ctx->r11 = mc->gregs[REG_R11];
    ctx->r12 = mc->gregs[REG_R12];
    ctx->r13 = mc->gregs[REG_R13];
    ctx->r14 = mc->gregs[REG_R14];
    ctx->r15 = mc->gregs[REG_R15];
    
    ctx->flags = mc->gregs[REG_EFL];
    
#elif defined(__aarch64__)
    const mcontext_t *mc = &uc->uc_mcontext;
    
    ctx->ip = (void *)mc->pc;
    ctx->sp = (void *)mc->sp;
    
    for (int i = 0; i < 30; i++) {
        ((uint64_t*)&ctx->rax)[i] = mc->regs[i];
    }
#else
    #warning "Register capture not implemented for this architecture"
    ctx->ip = NULL;
    ctx->sp = NULL;
    ctx->bp = NULL;
#endif
}

/**
 * Generate a human-readable stack trace using backtrace().
 */
static void aegis_generate_stack_trace(char *buffer, size_t size)
{
    void *frames[64];
    int nptrs = backtrace(frames, AEGIS_ARRAY_SIZE(frames));
    
    char **symbols = backtrace_symbols(frames, nptrs);
    if (!symbols) {
        snprintf(buffer, size, "[Failed to retrieve symbols]");
        return;
    }

    size_t offset = 0;
    for (int i = 0; i < nptrs && offset < size - 1; i++) {
        int written = snprintf(buffer + offset, size - offset, "  [%d] %s\n", i, symbols[i]);
        if (written < 0 || (size_t)written >= size - offset) {
            break;
        }
        offset += written;
    }

    free(symbols);
}

/**
 * Generate a unique crash ID based on instruction pointer and signal.
 * Uses a simple hash function suitable for deduplication.
 */
aegis_status_t aegis_crash_generate_id(const aegis_crash_context_t *ctx, char *id_out, size_t id_len)
{
    if (!ctx || !id_out || id_len < 17) {
        return AEGIS_ERR_INVALID_ARG;
    }

    /* Simple FNV-1a inspired hash of key registers */
    uint64_t hash = 14695981039346656037ULL;
    const uint8_t *data = (const uint8_t *)&ctx->ip;
    
    /* Hash IP */
    for (size_t i = 0; i < sizeof(void*); i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }
    
    /* Hash signal number */
    hash ^= (uint8_t)ctx->signum;
    hash *= 1099511628211ULL;
    
    /* Hash fault address if present */
    if (ctx->addr) {
        data = (const uint8_t *)&ctx->addr;
        for (size_t i = 0; i < sizeof(void*); i++) {
            hash ^= data[i];
            hash *= 1099511628211ULL;
        }
    }

    snprintf(id_out, id_len, "%016llx", (unsigned long long)hash);
    return AEGIS_OK;
}

/**
 * Write crash report to JSON file in the crashes directory.
 */
static void aegis_write_crash_report(const aegis_crash_report_t *report)
{
    char filename[1024];
    snprintf(filename, sizeof(filename), "%s/crash_%s.json", 
             AEGIS_DIR_CRASHES, report->id);

    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        AEGIS_LOG("Failed to create crash report file: %s", strerror(errno));
        return;
    }

    char buffer[8192];
    int len = snprintf(buffer, sizeof(buffer),
        "{\n"
        "  \"id\": \"%s\",\n"
        "  \"severity\": %d,\n"
        "  \"signal\": %d,\n"
        "  \"timestamp\": %lu,\n"
        "  \"target\": \"%s\",\n"
        "  \"input_size\": %lu,\n"
        "  \"input_path\": \"%s\",\n"
        "  \"registers\": {\n"
        "    \"ip\": \"0x%lx\",\n"
        "    \"sp\": \"0x%lx\",\n"
        "    \"bp\": \"0x%lx\",\n"
        "    \"rax\": \"0x%lx\",\n"
        "    \"rbx\": \"0x%lx\",\n"
        "    \"rcx\": \"0x%lx\",\n"
        "    \"rdx\": \"0x%lx\"\n"
        "  },\n"
        "  \"stack_trace\": \"%s\"\n"
        "}\n",
        report->id,
        report->severity,
        report->context.signum,
        (unsigned long)report->timestamp,
        report->target_name,
        (unsigned long)report->input_size,
        report->input_path,
        (unsigned long)report->context.ip,
        (unsigned long)report->context.sp,
        (unsigned long)report->context.bp,
        (unsigned long)report->context.rax,
        (unsigned long)report->context.rbx,
        (unsigned long)report->context.rcx,
        (unsigned long)report->context.rdx,
        report->stack_trace
    );

    if (len > 0 && (size_t)len < sizeof(buffer)) {
        write(fd, buffer, len);
    }

    close(fd);
    AEGIS_LOG("Crash report saved: %s", filename);
}
