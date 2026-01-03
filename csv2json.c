/*
 * csv2json — CSV to JSON converter with delimiter auto-detection
 *
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} sbuf_t;

static void die(const char *msg) {
    perror(msg);
    exit(1);
}

static void *xmalloc(size_t n) {
    void *p = malloc(n);
    if (!p) die("malloc");
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n);
    if (!q) die("realloc");
    return q;
}

static char *xstrdup(const char *s) {
    size_t n = strlen(s) + 1;
    char *p = (char *)xmalloc(n);
    memcpy(p, s, n);
    return p;
}

static void sbuf_init(sbuf_t *b) {
    b->cap = 512;
    b->len = 0;
    b->data = (char *)xmalloc(b->cap);
    b->data[0] = '\0';
}

static void sbuf_free(sbuf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

static void sbuf_reserve(sbuf_t *b, size_t need) {
    if (need <= b->cap) return;
    while (b->cap < need) b->cap *= 2;
    b->data = (char *)xrealloc(b->data, b->cap);
}

static void sbuf_pushc(sbuf_t *b, char c) {
    sbuf_reserve(b, b->len + 2);
    b->data[b->len++] = c;
    b->data[b->len] = '\0';
}

static void json_escape_and_print(FILE *out, const char *s) {
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        switch (c) {
            case '\\': fputs("\\\\", out); break;
            case '"':  fputs("\\\"", out); break;
            case '\b': fputs("\\b", out); break;
            case '\f': fputs("\\f", out); break;
            case '\n': fputs("\\n", out); break;
            case '\r': fputs("\\r", out); break;
            case '\t': fputs("\\t", out); break;
            default:
                if (c < 0x20) fprintf(out, "\\u%04x", c);
                else fputc(c, out);
        }
    }
    fputc('"', out);
}

/*
 * Read one CSV "record" as raw text, preserving embedded newlines inside quotes.
 * Returns malloc'd string without the terminating record newline/CRLF.
 * Returns NULL on EOF with no data read.
 */
static char *read_record_raw(FILE *in) {
    int c;
    int in_quotes = 0;
    int saw_any = 0;

    sbuf_t rec;
    sbuf_init(&rec);

    while (1) {
        c = fgetc(in);
        if (c == EOF) {
            if (!saw_any) {
                sbuf_free(&rec);
                return NULL;
            }
            break;
        }

        saw_any = 1;

        if (c == '"') {
            if (in_quotes) {
                int next = fgetc(in);
                if (next == '"') {
                    // Escaped quote inside quotes: keep both as-is in raw record ("")
                    sbuf_pushc(&rec, '"');
                    sbuf_pushc(&rec, '"');
                } else {
                    // End quotes: keep the quote, push back lookahead
                    sbuf_pushc(&rec, '"');
                    in_quotes = 0;
                    if (next != EOF) ungetc(next, in);
                }
            } else {
                // Begin quotes
                sbuf_pushc(&rec, '"');
                in_quotes = 1;
            }
            continue;
        }

        if (!in_quotes && (c == '\n' || c == '\r')) {
            if (c == '\r') {
                int next = fgetc(in);
                if (next != '\n' && next != EOF) ungetc(next, in);
            }
            break; // end of record
        }

        sbuf_pushc(&rec, (char)c);
    }

    char *out = xstrdup(rec.data);
    sbuf_free(&rec);
    return out;
}

/*
 * Count delimiter occurrences outside of quotes in a raw record.
 * Raw record may include "" sequences. We treat quotes as toggling, but "" should not toggle.
 */
static size_t count_delim_outside_quotes(const char *rec, char delim) {
    int in_quotes = 0;
    size_t cnt = 0;

    for (size_t i = 0; rec[i] != '\0'; i++) {
        char c = rec[i];

        if (c == '"') {
            if (in_quotes) {
                if (rec[i + 1] == '"') {
                    // escaped quote inside quotes
                    i++;
                } else {
                    in_quotes = 0;
                }
            } else {
                in_quotes = 1;
            }
            continue;
        }

        if (!in_quotes && c == delim) cnt++;
    }

    return cnt;
}

static char detect_delimiter(const char *first_record) {
    // Priority order for tie-breaks (common in the wild)
    const char candidates[] = { ',', '\t', ';', '|' };
    size_t best_count = 0;
    char best = ',';

    for (size_t i = 0; i < sizeof(candidates); i++) {
        char d = candidates[i];
        size_t c = count_delim_outside_quotes(first_record, d);
        if (c > best_count) {
            best_count = c;
            best = d;
        }
    }

    // If nothing found, default to comma.
    return best;
}

/*
 * Skip only truly blank lines (empty/whitespace-only).
 * Important: do NOT skip delimiter-only lines like ",,," or "\t\t" (those represent empty fields).
 */
static int is_blank_record(const char *rec, char delim) {
    int saw_delim = 0;

    for (const unsigned char *p = (const unsigned char *)rec; *p; p++) {
        if (*p == (unsigned char)delim) saw_delim = 1;
        if (!isspace(*p) && *p != (unsigned char)delim) {
            return 0; // has non-whitespace content -> not blank
        }
    }

    return saw_delim ? 0 : 1;
}

/*
 * Parse a raw record string into fields using delimiter.
 * Handles quoted fields, delimiter/newlines inside quotes, and "" -> " unescaping.
 */
static void parse_record_fields(const char *rec, char delim, char ***out_fields, size_t *out_nfields) {
    size_t cap = 16, n = 0;
    char **fields = (char **)xmalloc(sizeof(char *) * cap);

    sbuf_t field;
    sbuf_init(&field);

    int in_quotes = 0;

    for (size_t i = 0; ; i++) {
        char c = rec[i];

        if (c == '\0') {
            if (n == cap) {
                cap *= 2;
                fields = (char **)xrealloc(fields, sizeof(char *) * cap);
            }
            fields[n++] = xstrdup(field.data);
            break;
        }

        if (in_quotes) {
            if (c == '"') {
                if (rec[i + 1] == '"') {
                    sbuf_pushc(&field, '"');
                    i++;
                } else {
                    in_quotes = 0;
                }
            } else {
                sbuf_pushc(&field, c);
            }
            continue;
        }

        if (c == '"') {
            in_quotes = 1;
            continue;
        }

        if (c == delim) {
            if (n == cap) {
                cap *= 2;
                fields = (char **)xrealloc(fields, sizeof(char *) * cap);
            }
            fields[n++] = xstrdup(field.data);
            field.len = 0;
            field.data[0] = '\0';
            continue;
        }

        sbuf_pushc(&field, c);
    }

    sbuf_free(&field);
    *out_fields = fields;
    *out_nfields = n;
}

static void free_fields(char **fields, size_t nfields) {
    for (size_t i = 0; i < nfields; i++) free(fields[i]);
    free(fields);
}

static int is_json_number(const char *s) {
    while (isspace((unsigned char)*s)) s++;
    if (*s == '\0') return 0;

    const char *p = s;
    if (*p == '+' || *p == '-') p++;

    int saw_digit = 0;
    while (isdigit((unsigned char)*p)) { saw_digit = 1; p++; }

    if (*p == '.') {
        p++;
        while (isdigit((unsigned char)*p)) { saw_digit = 1; p++; }
    }

    if (!saw_digit) return 0;

    if (*p == 'e' || *p == 'E') {
        p++;
        if (*p == '+' || *p == '-') p++;
        int exp_digit = 0;
        while (isdigit((unsigned char)*p)) { exp_digit = 1; p++; }
        if (!exp_digit) return 0;
    }

    while (isspace((unsigned char)*p)) p++;
    return *p == '\0';
}

static void print_value(FILE *out, const char *v, int infer_types) {
    if (!infer_types) {
        json_escape_and_print(out, v);
        return;
    }

    const char *p = v;
    while (isspace((unsigned char)*p)) p++;
    if (*p == '\0') { fputs("null", out); return; }

    if (!strcasecmp(p, "true"))  { fputs("true", out);  return; }
    if (!strcasecmp(p, "false")) { fputs("false", out); return; }
    if (!strcasecmp(p, "null"))  { fputs("null", out);  return; }

    if (is_json_number(p)) { fputs(p, out); return; }

    json_escape_and_print(out, v);
}

static void usage(FILE *out) {
    fprintf(out,
        "csv2json - Convert CSV to JSON (NDJSON by default), delimiter auto-detected from first record\n\n"
        "Usage:\n"
        "  csv2json [--array] [--no-header] [--infer-types] [file.csv]\n\n"
        "Options:\n"
        "  --array         Output a single JSON array instead of NDJSON\n"
        "  --no-header     Treat first row as data (auto keys: col1..colN)\n"
        "  --infer-types   Convert empty->null, numbers->number, true/false/null literals\n"
        "  -h, --help      Show help\n\n"
        "Delimiter detection:\n"
        "  Auto-detects among: comma (,), tab (\\t), semicolon (;), pipe (|)\n"
        "  based on the first non-blank record (outside of quotes).\n\n"
        "Blank lines:\n"
        "  Truly blank/whitespace-only lines are skipped.\n"
        "  Delimiter-only lines like \",,,\" are NOT skipped (they represent empty fields).\n"
    );
}

int main(int argc, char **argv) {
    int out_array = 0;
    int no_header = 0;
    int infer_types = 0;
    const char *path = NULL;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--array")) out_array = 1;
        else if (!strcmp(argv[i], "--no-header")) no_header = 1;
        else if (!strcmp(argv[i], "--infer-types")) infer_types = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(stdout);
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(stderr);
            return 2;
        } else {
            path = argv[i];
        }
    }

    FILE *in = stdin;
    if (path) {
        in = fopen(path, "rb");
        if (!in) { perror("fopen"); return 1; }
    }

    // Read first meaningful record raw (skip empty/whitespace-only lines)
    char *first_rec = NULL;
    while (1) {
        first_rec = read_record_raw(in);
        if (!first_rec) {
            if (out_array) fputs("[]\n", stdout);
            if (path) fclose(in);
            return 0;
        }

        int only_ws = 1;
        for (const unsigned char *p = (const unsigned char *)first_rec; *p; p++) {
            if (!isspace(*p)) { only_ws = 0; break; }
        }

        if (!only_ws) break;

        free(first_rec);
        first_rec = NULL;
    }

    // Auto-detect delimiter from the first meaningful record
    char delim = detect_delimiter(first_rec);

    // Parse first record into fields
    char **row = NULL;
    size_t nrow = 0;
    parse_record_fields(first_rec, delim, &row, &nrow);
    free(first_rec);

    // Determine headers
    char **headers = NULL;
    size_t nheaders = 0;

    if (!no_header) {
        headers = row;
        nheaders = nrow;

        for (size_t i = 0; i < nheaders; i++) {
            if (headers[i][0] == '\0') {
                char tmp[64];
                snprintf(tmp, sizeof(tmp), "col%zu", i + 1);
                free(headers[i]);
                headers[i] = xstrdup(tmp);
            }
        }

        row = NULL;
        nrow = 0;
    } else {
        nheaders = nrow;
        headers = (char **)xmalloc(sizeof(char *) * nheaders);
        for (size_t i = 0; i < nheaders; i++) {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), "col%zu", i + 1);
            headers[i] = xstrdup(tmp);
        }
    }

    int first_out = 1;
    if (out_array) fputc('[', stdout);

    // If --no-header, the first parsed row is data and must be output (unless it was blank)
    if (no_header) {
        // Note: we intentionally did not treat delimiter-only records as blank.
        // first row already parsed into nrow fields and should be output.
        if (out_array) {
            if (!first_out) fputc(',', stdout);
        }

        fputc('{', stdout);
        for (size_t i = 0; i < nheaders; i++) {
            if (i) fputc(',', stdout);
            json_escape_and_print(stdout, headers[i]);
            fputc(':', stdout);
            if (i < nrow) print_value(stdout, row[i], infer_types);
            else fputs("null", stdout);
        }
        fputc('}', stdout);

        if (out_array) first_out = 0;
        else fputc('\n', stdout);

        free_fields(row, nrow);
        row = NULL;
        nrow = 0;
    }

    // Process remaining records
    while (1) {
        char *rec = read_record_raw(in);
        if (!rec) break;

        if (is_blank_record(rec, delim)) {
            free(rec);
            continue; // skip truly blank lines
        }

        parse_record_fields(rec, delim, &row, &nrow);
        free(rec);

        if (out_array) {
            if (!first_out) fputc(',', stdout);
        }

        fputc('{', stdout);
        for (size_t i = 0; i < nheaders; i++) {
            if (i) fputc(',', stdout);
            json_escape_and_print(stdout, headers[i]);
            fputc(':', stdout);
            if (i < nrow) print_value(stdout, row[i], infer_types);
            else fputs("null", stdout);
        }
        fputc('}', stdout);

        if (out_array) first_out = 0;
        else fputc('\n', stdout);

        free_fields(row, nrow);
        row = NULL;
        nrow = 0;
    }

    if (out_array) fputs("]\n", stdout);

    if (!no_header) {
        free_fields(headers, nheaders);
    } else {
        for (size_t i = 0; i < nheaders; i++) free(headers[i]);
        free(headers);
    }

    if (path) fclose(in);
    return 0;
}
