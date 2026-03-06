// auth.c
// Compile: see instructions below
// Mirrors Node auth.js behavior: credential check, token fetch, HttpOnly cookie,
// SameSite=Strict, Max-Age=300, CORS, OPTIONS preflight.
// Uses libmicrohttpd, jansson, libcurl with per-thread CURL handles (pthread_key_t).

#include <microhttpd.h>
#include <jansson.h>
#include <curl/curl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define PORT 5050
#define TOKEN_SERVICE_URL "http://127.0.0.1:6060/api/token"
#define MAX_POST_SIZE (10 * 1024 * 1024) // 10MB

struct User {
    const char *email;
    const char *password;
};

struct User users[] = {
    { "abc@test.com", "password" },
    { "john@test", "password" }
};
const size_t users_count = sizeof(users) / sizeof(users[0]);

/* libcurl response buffer */
struct curl_buffer {
    char *data;
    size_t size;
};

static size_t curl_write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct curl_buffer *buf = (struct curl_buffer *)userp;
    char *ptr = realloc(buf->data, buf->size + realsize + 1);
    if (!ptr) return 0;
    buf->data = ptr;
    memcpy(&(buf->data[buf->size]), contents, realsize);
    buf->size += realsize;
    buf->data[buf->size] = 0;
    return realsize;
}

/* Thread-local CURL handle using pthread_key_t */
static pthread_key_t curl_key;
static int curl_key_initialized = 0;

static void curl_thread_destructor(void *ptr) {
    CURL *c = (CURL *)ptr;
    if (c) {
        curl_easy_cleanup(c);
    }
}

static void init_thread_local_curl_key(void) {
    if (!curl_key_initialized) {
        if (pthread_key_create(&curl_key, curl_thread_destructor) == 0) {
            curl_key_initialized = 1;
        }
    }
}

/* Get or create thread-local CURL handle; reset and set persistent options */
static CURL *get_thread_curl(void) {
    if (!curl_key_initialized) return NULL;
    CURL *c = (CURL *)pthread_getspecific(curl_key);
    if (!c) {
        c = curl_easy_init();
        if (!c) return NULL;
        /* persistent options */
        curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 2L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 5L);
        pthread_setspecific(curl_key, c);
    } else {
        /* reset to clean state and reapply persistent options */
        curl_easy_reset(c);
        curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT, 2L);
        curl_easy_setopt(c, CURLOPT_TIMEOUT, 5L);
    }
    return c;
}

/* Call token service and return token string (caller must free) or NULL */
static char *fetch_token_for_email(const char *email) {
    CURL *curl = get_thread_curl();
    if (!curl) return NULL;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    json_t *root = json_object();
    json_object_set_new(root, "email", json_string(email));
    char *payload = json_dumps(root, 0);
    json_decref(root);

    struct curl_buffer buf = { .data = NULL, .size = 0 };

    curl_easy_setopt(curl, CURLOPT_URL, TOKEN_SERVICE_URL);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    /* timeouts and NOSIGNAL already set in get_thread_curl; reassert to be safe */
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);

    CURLcode res = curl_easy_perform(curl);
    free(payload);
    curl_slist_free_all(headers);

    if (res != CURLE_OK) {
        if (buf.data) free(buf.data);
        return NULL;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code < 200 || http_code >= 300) {
        if (buf.data) free(buf.data);
        return NULL;
    }

    json_error_t err;
    json_t *resp = json_loads(buf.data ? buf.data : "{}", 0, &err);
    if (buf.data) free(buf.data);
    if (!resp) return NULL;

    json_t *token_j = json_object_get(resp, "token");
    if (!json_is_string(token_j)) {
        json_decref(resp);
        return NULL;
    }

    const char *token_str = json_string_value(token_j);
    char *ret = strdup(token_str);
    json_decref(resp);
    return ret;
}

/* Add CORS headers */
static void add_cors_headers(struct MHD_Response *response) {
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "http://localhost:3000");
    MHD_add_response_header(response, "Access-Control-Allow-Credentials", "true");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type");
}

/* Request handler */
static enum MHD_Result handle_request(void *cls, struct MHD_Connection *connection,
                                      const char *url, const char *method,
                                      const char *version, const char *upload_data,
                                      size_t *upload_data_size, void **con_cls) {
    if (0 == strcmp(method, "OPTIONS")) {
        struct MHD_Response *resp = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
        add_cors_headers(resp);
        int ret = MHD_queue_response(connection, MHD_HTTP_OK, resp);
        MHD_destroy_response(resp);
        return ret == MHD_YES ? MHD_YES : MHD_NO;
    }

    if (0 == strcmp(url, "/api/login") && 0 == strcmp(method, "POST")) {
        if (*con_cls == NULL) {
            char **bufp = malloc(sizeof(char *));
            if (!bufp) return MHD_NO;
            *bufp = NULL;
            *con_cls = bufp;
            return MHD_YES;
        }

        char **bufp = (char **)*con_cls;

        if (*upload_data_size > 0) {
            size_t old_len = *bufp ? strlen(*bufp) : 0;
            size_t add_len = *upload_data_size;
            if (old_len + add_len > MAX_POST_SIZE) {
                const char *msg = "{\"success\":false,\"message\":\"Payload too large\"}";
                struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_PERSISTENT);
                add_cors_headers(resp);
                MHD_add_response_header(resp, "Content-Type", "application/json");
                int ret = MHD_queue_response(connection, MHD_HTTP_REQUEST_ENTITY_TOO_LARGE, resp);
                MHD_destroy_response(resp);
                return ret == MHD_YES ? MHD_YES : MHD_NO;
            }
            char *newbuf = realloc(*bufp, old_len + add_len + 1);
            if (!newbuf) return MHD_NO;
            memcpy(newbuf + old_len, upload_data, add_len);
            newbuf[old_len + add_len] = 0;
            *bufp = newbuf;
            *upload_data_size = 0;
            return MHD_YES;
        } else {
            const char *body = *bufp ? *bufp : "{}";
            json_error_t err;
            json_t *root = json_loads(body, 0, &err);
            free(*bufp);
            free(bufp);
            *con_cls = NULL;

            if (!root) {
                const char *msg = "{\"success\":false,\"message\":\"Invalid JSON\"}";
                struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_PERSISTENT);
                add_cors_headers(resp);
                MHD_add_response_header(resp, "Content-Type", "application/json");
                int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, resp);
                MHD_destroy_response(resp);
                return ret == MHD_YES ? MHD_YES : MHD_NO;
            }

            json_t *email_j = json_object_get(root, "email");
            json_t *password_j = json_object_get(root, "password");
            const char *email = json_is_string(email_j) ? json_string_value(email_j) : NULL;
            const char *password = json_is_string(password_j) ? json_string_value(password_j) : NULL;

            if (!email || !password) {
                json_decref(root);
                const char *msg = "{\"success\":false,\"message\":\"Missing credentials\"}";
                struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_PERSISTENT);
                add_cors_headers(resp);
                MHD_add_response_header(resp, "Content-Type", "application/json");
                int ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, resp);
                MHD_destroy_response(resp);
                return ret == MHD_YES ? MHD_YES : MHD_NO;
            }

            int found = 0;
            for (size_t i = 0; i < users_count; ++i) {
                if (strcmp(users[i].email, email) == 0 && strcmp(users[i].password, password) == 0) {
                    found = 1;
                    break;
                }
            }

            if (!found) {
                json_decref(root);
                const char *msg = "{\"success\":false,\"message\":\"Invalid credentials\"}";
                struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_PERSISTENT);
                add_cors_headers(resp);
                MHD_add_response_header(resp, "Content-Type", "application/json");
                int ret = MHD_queue_response(connection, MHD_HTTP_UNAUTHORIZED, resp);
                MHD_destroy_response(resp);
                return ret == MHD_YES ? MHD_YES : MHD_NO;
            }

            /* Fetch token from token service */
            char *token = fetch_token_for_email(email);
            if (!token) {
                json_decref(root);
                const char *msg = "{\"success\":false,\"message\":\"Token service unavailable\"}";
                struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_PERSISTENT);
                add_cors_headers(resp);
                MHD_add_response_header(resp, "Content-Type", "application/json");
                int ret = MHD_queue_response(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, resp);
                MHD_destroy_response(resp);
                return ret == MHD_YES ? MHD_YES : MHD_NO;
            }

            /* Build Set-Cookie header */
            char cookie_header[4096];
            const char *secure = "";
            const char *node_env = getenv("NODE_ENV");
            if (node_env && strcmp(node_env, "production") == 0) {
                secure = " Secure";
            }
            /* Format: authToken=...; HttpOnly; SameSite=Strict; Max-Age=300; [Secure] */
            snprintf(cookie_header, sizeof(cookie_header),
                     "authToken=%s; HttpOnly; SameSite=Strict; Max-Age=300;%s",
                     token, secure);

            free(token);
            json_decref(root);

            const char *msg = "{\"success\":true,\"message\":\"login success\"}";
            struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_PERSISTENT);
            add_cors_headers(resp);
            MHD_add_response_header(resp, "Content-Type", "application/json");
            MHD_add_response_header(resp, "Set-Cookie", cookie_header);

            int ret = MHD_queue_response(connection, MHD_HTTP_OK, resp);
            MHD_destroy_response(resp);
            return ret == MHD_YES ? MHD_YES : MHD_NO;
        }
    }

    const char *msg = "{\"success\":false,\"message\":\"Not found\"}";
    struct MHD_Response *resp = MHD_create_response_from_buffer(strlen(msg), (void*)msg, MHD_RESPMEM_PERSISTENT);
    add_cors_headers(resp);
    MHD_add_response_header(resp, "Content-Type", "application/json");
    int ret = MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, resp);
    MHD_destroy_response(resp);
    return ret == MHD_YES ? MHD_YES : MHD_NO;
}

int main(void) {
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        fprintf(stderr, "curl_global_init failed\n");
        return 1;
    }

    init_thread_local_curl_key();

    struct MHD_Daemon *daemon = MHD_start_daemon(
        MHD_USE_SELECT_INTERNALLY,
        PORT,
        NULL, NULL,
        &handle_request, NULL,
        MHD_OPTION_THREAD_POOL_SIZE, 500, /* tune as needed */
        MHD_OPTION_END);

    if (!daemon) {
        fprintf(stderr, "Failed to start server on port %d\n", PORT);
        curl_global_cleanup();
        return 1;
    }

    printf("Auth service running on http://localhost:%d\n", PORT);
    printf("Press Enter to stop...\n");
    getchar();

    MHD_stop_daemon(daemon);
    /* delete key; thread destructors will run when threads exit */
    pthread_key_delete(curl_key);
    curl_global_cleanup();
    return 0;
}