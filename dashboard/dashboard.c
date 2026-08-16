/**
 * Mini-AFL Dashboard - Real-time Web Interface
 * 
 * Provides real-time reporting of crash logs, vulnerability trends, and fuzzing statistics.
 * Exposes REST API for CI/CD integration and cloud deployment.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#define DASHBOARD_PORT 8080
#define MAX_CRASHES 1000
#define MAX_STATS_HISTORY 3600

typedef struct {
    char id[64];
    int signal;
    char classification[32];
    char stack_hash[16];
    time_t first_seen;
    time_t last_seen;
    int occurrence_count;
    char input_path[256];
    bool minimized;
    bool verified;
} crash_entry_t;

typedef struct {
    uint64_t total_executions;
    uint64_t crashes_found;
    uint64_t unique_crashes;
    uint64_t edges_discovered;
    uint64_t total_edges;
    double execs_per_sec;
    double crash_rate;
    time_t start_time;
    time_t last_update;
} fuzz_stats_t;

typedef struct {
    crash_entry_t crashes[MAX_CRASHES];
    int crash_count;
    fuzz_stats_t stats;
    pthread_mutex_t lock;
    char output_dir[512];
    bool running;
} dashboard_state_t;

static dashboard_state_t g_dashboard = {0};

/**
 * Initialize dashboard state
 */
int dashboard_init(const char *output_dir) {
    pthread_mutex_init(&g_dashboard.lock, NULL);
    g_dashboard.crash_count = 0;
    g_dashboard.stats.start_time = time(NULL);
    g_dashboard.running = true;
    
    if (output_dir) {
        strncpy(g_dashboard.output_dir, output_dir, sizeof(g_dashboard.output_dir) - 1);
    } else {
        strcpy(g_dashboard.output_dir, "./crashes");
    }
    
    return 0;
}

/**
 * Add a new crash entry
 */
int dashboard_add_crash(crash_entry_t *crash) {
    pthread_mutex_lock(&g_dashboard.lock);
    
    if (g_dashboard.crash_count >= MAX_CRASHES) {
        pthread_mutex_unlock(&g_dashboard.lock);
        return -1;
    }
    
    memcpy(&g_dashboard.crashes[g_dashboard.crash_count], crash, sizeof(*crash));
    g_dashboard.crash_count++;
    g_dashboard.stats.crashes_found++;
    
    pthread_mutex_unlock(&g_dashboard.lock);
    return 0;
}

/**
 * Update fuzzing statistics
 */
void dashboard_update_stats(uint64_t execs, uint64_t edges, uint64_t total_edges) {
    pthread_mutex_lock(&g_dashboard.lock);
    
    g_dashboard.stats.total_executions = execs;
    g_dashboard.stats.edges_discovered = edges;
    g_dashboard.stats.total_edges = total_edges;
    g_dashboard.stats.last_update = time(NULL);
    
    time_t elapsed = time(NULL) - g_dashboard.stats.start_time;
    if (elapsed > 0) {
        g_dashboard.stats.execs_per_sec = (double)execs / elapsed;
    }
    
    if (execs > 0) {
        g_dashboard.stats.crash_rate = (double)g_dashboard.stats.crashes_found / execs * 100.0;
    }
    
    pthread_mutex_unlock(&g_dashboard.lock);
}

/**
 * Generate JSON response for crashes
 */
static void generate_crashes_json(char *buffer, size_t buf_size) {
    pthread_mutex_lock(&g_dashboard.lock);
    
    char *ptr = buffer;
    ptr += snprintf(ptr, buf_size - (ptr - buffer), "{\n  \"crashes\": [\n");
    
    for (int i = 0; i < g_dashboard.crash_count; i++) {
        crash_entry_t *c = &g_dashboard.crashes[i];
        ptr += snprintf(ptr, buf_size - (ptr - buffer),
            "    {\n"
            "      \"id\": \"%s\",\n"
            "      \"signal\": %d,\n"
            "      \"classification\": \"%s\",\n"
            "      \"stack_hash\": \"%s\",\n"
            "      \"first_seen\": %ld,\n"
            "      \"last_seen\": %ld,\n"
            "      \"occurrences\": %d,\n"
            "      \"minimized\": %s,\n"
            "      \"verified\": %s\n"
            "    }%s\n",
            c->id, c->signal, c->classification, c->stack_hash,
            (long)c->first_seen, (long)c->last_seen, c->occurrence_count,
            c->minimized ? "true" : "false",
            c->verified ? "true" : "false",
            (i < g_dashboard.crash_count - 1) ? "," : "");
    }
    
    ptr += snprintf(ptr, buf_size - (ptr - buffer), "  ]\n}\n");
    
    pthread_mutex_unlock(&g_dashboard.lock);
}

/**
 * Generate JSON response for statistics
 */
static void generate_stats_json(char *buffer, size_t buf_size) {
    pthread_mutex_lock(&g_dashboard.lock);
    
    snprintf(buffer, buf_size,
        "{\n"
        "  \"total_executions\": %lu,\n"
        "  \"crashes_found\": %lu,\n"
        "  \"unique_crashes\": %d,\n"
        "  \"edges_discovered\": %lu,\n"
        "  \"total_edges\": %lu,\n"
        "  \"execs_per_sec\": %.2f,\n"
        "  \"crash_rate\": %.4f,\n"
        "  \"uptime_seconds\": %ld,\n"
        "  \"last_update\": %ld\n"
        "}\n",
        (unsigned long)g_dashboard.stats.total_executions,
        (unsigned long)g_dashboard.stats.crashes_found,
        g_dashboard.crash_count,
        (unsigned long)g_dashboard.stats.edges_discovered,
        (unsigned long)g_dashboard.stats.total_edges,
        g_dashboard.stats.execs_per_sec,
        g_dashboard.stats.crash_rate,
        (long)(time(NULL) - g_dashboard.stats.start_time),
        (long)g_dashboard.stats.last_update);
    
    pthread_mutex_unlock(&g_dashboard.lock);
}

/**
 * Simple HTTP request handler
 */
static void handle_request(int client_fd) {
    char buffer[4096];
    char response[8192];
    
    ssize_t bytes_read = read(client_fd, buffer, sizeof(buffer) - 1);
    if (bytes_read <= 0) {
        return;
    }
    buffer[bytes_read] = '\0';
    
    /* Parse simple GET requests */
    if (strncmp(buffer, "GET /api/crashes", 16) == 0) {
        generate_crashes_json(response, sizeof(response));
        
        snprintf(buffer, sizeof(buffer),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "\r\n"
            "%s",
            strlen(response), response);
        write(client_fd, buffer, strlen(buffer));
        
    } else if (strncmp(buffer, "GET /api/stats", 14) == 0) {
        generate_stats_json(response, sizeof(response));
        
        snprintf(buffer, sizeof(buffer),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Content-Length: %zu\r\n"
            "\r\n"
            "%s",
            strlen(response), response);
        write(client_fd, buffer, strlen(buffer));
        
    } else if (strncmp(buffer, "GET /", 5) == 0) {
        /* Serve simple HTML dashboard */
        const char *html = 
            "<!DOCTYPE html>\n"
            "<html><head><title>Mini-AFL Dashboard</title>\n"
            "<meta http-equiv=\"refresh\" content=\"5\">\n"
            "<style>\n"
            "body { font-family: monospace; background: #1a1a1a; color: #0f0; padding: 20px; }\n"
            ".stat { margin: 10px 0; }\n"
            ".crash { border: 1px solid #333; padding: 10px; margin: 5px 0; }\n"
            "</style></head>\n"
            "<body>\n"
            "<h1>Mini-AFL Fuzzing Dashboard</h1>\n"
            "<div id=\"stats\">Loading...</div>\n"
            "<div id=\"crashes\">Loading...</div>\n"
            "<script>\n"
            "setInterval(function() {\n"
            "  fetch('/api/stats').then(r=>r.json()).then(d=>{\n"
            "    document.getElementById('stats').innerHTML = \n"
            "      '<h2>Statistics</h2>' +\n"
            "      '<div class=\"stat\">Executions: ' + d.total_executions + '</div>' +\n"
            "      '<div class=\"stat\">Crashes: ' + d.crashes_found + ' (unique: ' + d.unique_crashes + ')</div>' +\n"
            "      '<div class=\"stat\">Coverage: ' + d.edges_discovered + '/' + d.total_edges + ' edges</div>' +\n"
            "      '<div class=\"stat\">Speed: ' + d.execs_per_sec.toFixed(2) + ' execs/sec</div>';\n"
            "  });\n"
            "  fetch('/api/crashes').then(r=>r.json()).then(d=>{\n"
            "    let html = '<h2>Crashes</h2>';\n"
            "    d.crashes.forEach(c => {\n"
            "      html += '<div class=\"crash\">' + c.id + ' - ' + c.classification + \n"
            "              ' (signal: ' + c.signal + ', occurrences: ' + c.occurrences + ')' +\n"
            "              (c.verified ? ' ✓' : '') + '</div>';\n"
            "    });\n"
            "    document.getElementById('crashes').innerHTML = html;\n"
            "  });\n"
            "}, 5000);\n"
            "</script></body></html>";
        
        snprintf(buffer, sizeof(buffer),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/html\r\n"
            "Content-Length: %zu\r\n"
            "\r\n"
            "%s",
            strlen(html), html);
        write(client_fd, buffer, strlen(buffer));
    }
    
    close(client_fd);
}

/**
 * Dashboard server thread
 */
static void *dashboard_server_thread(void *arg) {
    int server_fd;
    struct sockaddr_in addr;
    int opt = 1;
    
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        fprintf(stderr, "Failed to create dashboard socket: %s\n", strerror(errno));
        return NULL;
    }
    
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(DASHBOARD_PORT);
    
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Failed to bind dashboard port %d: %s\n", DASHBOARD_PORT, strerror(errno));
        close(server_fd);
        return NULL;
    }
    
    if (listen(server_fd, 10) < 0) {
        fprintf(stderr, "Failed to listen on dashboard port: %s\n", strerror(errno));
        close(server_fd);
        return NULL;
    }
    
    printf("Dashboard listening on http://localhost:%d\n", DASHBOARD_PORT);
    
    while (g_dashboard.running) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(server_fd, &fds);
        
        struct timeval tv = {1, 0};
        int ret = select(server_fd + 1, &fds, NULL, NULL, &tv);
        
        if (ret > 0 && FD_ISSET(server_fd, &fds)) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
            
            if (client_fd >= 0) {
                handle_request(client_fd);
            }
        }
    }
    
    close(server_fd);
    return NULL;
}

/**
 * Start dashboard server
 */
int dashboard_start(void) {
    pthread_t thread;
    return pthread_create(&thread, NULL, dashboard_server_thread, NULL);
}

/**
 * Stop dashboard server
 */
void dashboard_stop(void) {
    g_dashboard.running = false;
    pthread_mutex_destroy(&g_dashboard.lock);
}

/* Export functions for use by fuzzer */
__attribute__((visibility("default")))
int mafl_dashboard_init(const char *output_dir) {
    return dashboard_init(output_dir);
}

__attribute__((visibility("default")))
int mafl_dashboard_add_crash(crash_entry_t *crash) {
    return dashboard_add_crash(crash);
}

__attribute__((visibility("default")))
void mafl_dashboard_update_stats(uint64_t execs, uint64_t edges, uint64_t total_edges) {
    dashboard_update_stats(execs, edges, total_edges);
}

__attribute__((visibility("default")))
int mafl_dashboard_start(void) {
    return dashboard_start();
}

__attribute__((visibility("default")))
void mafl_dashboard_stop(void) {
    dashboard_stop();
}
