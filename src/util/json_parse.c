/*
 * json_parse.c -- the recursive-descent parser behind tamga_json_parse().
 *
 * Strict by construction. Everything a lenient JSON parser might accept as a
 * convenience -- comments, trailing commas, single-quoted strings, NaN,
 * Infinity, leading '+', leading zeros, unescaped control characters, lone
 * surrogates, invalid UTF-8 -- is rejected, because each one is a place where
 * this parser and the server's could disagree about what a document means,
 * and one of those documents carries a signature.
 */
#include "util/json.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "tamga.h"
#include "tamga_mem.h"
#include "util/buf.h"

/* Longest numeric token accepted. A double needs at most ~325 characters to
 * write out in full; past that the token cannot be meaningful. */
#define TAMGA_JSON_MAX_NUMBER_CHARS 340

typedef struct TamgaJsonParser {
    const char *text;
    size_t len;
    size_t pos;
    unsigned int depth;
    const char *error;
} TamgaJsonParser;

static TamgaJson *tamga_json_parse_value(TamgaJsonParser *p);

/* One shared object, so the caller can tell an allocation failure from a
 * malformed document by comparing the pointer rather than the text. Every
 * allocation failure in this file reports through it. */
const char TAMGA_JSON_ERROR_OUT_OF_MEMORY[] = "out of memory";

bool tamga_json_error_is_out_of_memory(const char *error) {
    return error == TAMGA_JSON_ERROR_OUT_OF_MEMORY;
}

static void tamga_json_fail(TamgaJsonParser *p, const char *message) {
    if (p->error == NULL) {
        p->error = message;
    }
}

static bool tamga_json_at_end(const TamgaJsonParser *p) {
    return p->pos >= p->len;
}

static char tamga_json_peek(const TamgaJsonParser *p) {
    return tamga_json_at_end(p) ? '\0' : p->text[p->pos];
}

/* Only the four characters RFC 8259 calls whitespace. Notably not vertical
 * tab or form feed, which some parsers accept. */
static void tamga_json_skip_ws(TamgaJsonParser *p) {
    while (!tamga_json_at_end(p)) {
        char c = p->text[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            p->pos++;
        } else {
            return;
        }
    }
}

static bool tamga_json_match_literal(TamgaJsonParser *p, const char *literal) {
    size_t n = strlen(literal);
    if ((p->len - p->pos) < n) {
        return false;
    }
    if (memcmp(&p->text[p->pos], literal, n) != 0) {
        return false;
    }
    p->pos += n;
    return true;
}

/* --- UTF-8 -------------------------------------------------------------- */

/*
 * Validates one UTF-8 sequence at `text[0]` and returns its length, or 0 if
 * it is malformed. Rejects overlong encodings, surrogate code points and
 * anything above U+10FFFF -- all three are accepted by naive decoders, and
 * all three let two implementations disagree about the bytes of "the same"
 * string.
 */
static size_t tamga_utf8_sequence_len(const unsigned char *text, size_t available) {
    unsigned char b0;

    if (available == 0u) {
        return 0u;
    }
    b0 = text[0];
    if (b0 < 0x80u) {
        return 1u;
    }
    if (b0 >= 0xC2u && b0 <= 0xDFu) {
        if (available < 2u || (text[1] & 0xC0u) != 0x80u) {
            return 0u;
        }
        return 2u;
    }
    if (b0 >= 0xE0u && b0 <= 0xEFu) {
        unsigned char lower = (b0 == 0xE0u) ? 0xA0u : 0x80u;
        unsigned char upper = (b0 == 0xEDu) ? 0x9Fu : 0xBFu; /* excludes surrogates */
        if (available < 3u) {
            return 0u;
        }
        if (text[1] < lower || text[1] > upper) {
            return 0u;
        }
        if ((text[2] & 0xC0u) != 0x80u) {
            return 0u;
        }
        return 3u;
    }
    if (b0 >= 0xF0u && b0 <= 0xF4u) {
        unsigned char lower = (b0 == 0xF0u) ? 0x90u : 0x80u;
        unsigned char upper = (b0 == 0xF4u) ? 0x8Fu : 0xBFu; /* caps at U+10FFFF */
        if (available < 4u) {
            return 0u;
        }
        if (text[1] < lower || text[1] > upper) {
            return 0u;
        }
        if ((text[2] & 0xC0u) != 0x80u || (text[3] & 0xC0u) != 0x80u) {
            return 0u;
        }
        return 4u;
    }
    return 0u;
}

static void tamga_utf8_encode(uint32_t codepoint, TamgaBuf *out) {
    if (codepoint < 0x80u) {
        tamga_buf_append_byte(out, (unsigned char)codepoint);
    } else if (codepoint < 0x800u) {
        tamga_buf_append_byte(out, (unsigned char)(0xC0u | (codepoint >> 6)));
        tamga_buf_append_byte(out, (unsigned char)(0x80u | (codepoint & 0x3Fu)));
    } else if (codepoint < 0x10000u) {
        tamga_buf_append_byte(out, (unsigned char)(0xE0u | (codepoint >> 12)));
        tamga_buf_append_byte(out, (unsigned char)(0x80u | ((codepoint >> 6) & 0x3Fu)));
        tamga_buf_append_byte(out, (unsigned char)(0x80u | (codepoint & 0x3Fu)));
    } else {
        tamga_buf_append_byte(out, (unsigned char)(0xF0u | (codepoint >> 18)));
        tamga_buf_append_byte(out, (unsigned char)(0x80u | ((codepoint >> 12) & 0x3Fu)));
        tamga_buf_append_byte(out, (unsigned char)(0x80u | ((codepoint >> 6) & 0x3Fu)));
        tamga_buf_append_byte(out, (unsigned char)(0x80u | (codepoint & 0x3Fu)));
    }
}

static bool tamga_json_read_hex4(TamgaJsonParser *p, uint32_t *out) {
    uint32_t value = 0u;
    size_t i;

    if ((p->len - p->pos) < 4u) {
        return false;
    }
    for (i = 0u; i < 4u; i++) {
        char c = p->text[p->pos + i];
        uint32_t digit;
        if (c >= '0' && c <= '9') {
            digit = (uint32_t)(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = (uint32_t)((c - 'a') + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = (uint32_t)((c - 'A') + 10);
        } else {
            return false;
        }
        value = (value << 4) | digit;
    }
    p->pos += 4u;
    *out = value;
    return true;
}

/* --- strings ------------------------------------------------------------ */

/* Parses a string token (the opening quote must be the current character)
 * into `out`, leaving the parser just past the closing quote. */
static bool tamga_json_parse_string_into(TamgaJsonParser *p, TamgaBuf *out) {
    if (tamga_json_peek(p) != '"') {
        tamga_json_fail(p, "expected a string");
        return false;
    }
    p->pos++;

    for (;;) {
        unsigned char c;

        if (tamga_json_at_end(p)) {
            tamga_json_fail(p, "unterminated string");
            return false;
        }
        c = (unsigned char)p->text[p->pos];

        if (c == '"') {
            p->pos++;
            return tamga_buf_ok(out);
        }

        if (c == '\\') {
            char esc;
            p->pos++;
            if (tamga_json_at_end(p)) {
                tamga_json_fail(p, "unterminated escape sequence");
                return false;
            }
            esc = p->text[p->pos];
            p->pos++;
            switch (esc) {
            case '"':
                tamga_buf_append_byte(out, '"');
                break;
            case '\\':
                tamga_buf_append_byte(out, '\\');
                break;
            case '/':
                tamga_buf_append_byte(out, '/');
                break;
            case 'b':
                tamga_buf_append_byte(out, '\b');
                break;
            case 'f':
                tamga_buf_append_byte(out, '\f');
                break;
            case 'n':
                tamga_buf_append_byte(out, '\n');
                break;
            case 'r':
                tamga_buf_append_byte(out, '\r');
                break;
            case 't':
                tamga_buf_append_byte(out, '\t');
                break;
            case 'u': {
                uint32_t unit;
                if (!tamga_json_read_hex4(p, &unit)) {
                    tamga_json_fail(p, "malformed unicode escape");
                    return false;
                }
                if (unit >= 0xD800u && unit <= 0xDBFFu) {
                    uint32_t low;
                    /* High surrogate: a low surrogate must follow, as its own
                     * escape. A lone surrogate is not a character and has no
                     * valid UTF-8 encoding. */
                    if ((p->len - p->pos) < 6u || p->text[p->pos] != '\\' ||
                        p->text[p->pos + 1u] != 'u') {
                        tamga_json_fail(p, "unpaired high surrogate");
                        return false;
                    }
                    p->pos += 2u;
                    if (!tamga_json_read_hex4(p, &low)) {
                        tamga_json_fail(p, "malformed unicode escape");
                        return false;
                    }
                    if (low < 0xDC00u || low > 0xDFFFu) {
                        tamga_json_fail(p, "unpaired high surrogate");
                        return false;
                    }
                    unit = 0x10000u + ((unit - 0xD800u) << 10) + (low - 0xDC00u);
                } else if (unit >= 0xDC00u && unit <= 0xDFFFu) {
                    tamga_json_fail(p, "unpaired low surrogate");
                    return false;
                }
                tamga_utf8_encode(unit, out);
                break;
            }
            default:
                tamga_json_fail(p, "unknown escape sequence");
                return false;
            }
            continue;
        }

        if (c < 0x20u) {
            /* RFC 8259: control characters must be escaped. */
            tamga_json_fail(p, "unescaped control character in string");
            return false;
        }

        {
            size_t seq =
                tamga_utf8_sequence_len((const unsigned char *)&p->text[p->pos], p->len - p->pos);
            if (seq == 0u) {
                tamga_json_fail(p, "invalid UTF-8 in string");
                return false;
            }
            tamga_buf_append(out, &p->text[p->pos], seq);
            p->pos += seq;
        }
    }
}

/* --- numbers ------------------------------------------------------------ */

static TamgaJson *tamga_json_parse_number(TamgaJsonParser *p) {
    size_t start = p->pos;
    size_t token_len;
    bool is_integer = true;
    char token[TAMGA_JSON_MAX_NUMBER_CHARS + 1];

    if (tamga_json_peek(p) == '-') {
        p->pos++;
    }

    /* Integer part: either a single '0' or a non-zero-leading digit run.
     * "01" is not valid JSON, and accepting it would let two textually
     * different documents mean the same thing. */
    if (tamga_json_peek(p) == '0') {
        p->pos++;
    } else if (tamga_json_peek(p) >= '1' && tamga_json_peek(p) <= '9') {
        while (tamga_json_peek(p) >= '0' && tamga_json_peek(p) <= '9') {
            p->pos++;
        }
    } else {
        tamga_json_fail(p, "malformed number");
        return NULL;
    }

    if (tamga_json_peek(p) == '.') {
        is_integer = false;
        p->pos++;
        if (!(tamga_json_peek(p) >= '0' && tamga_json_peek(p) <= '9')) {
            tamga_json_fail(p, "malformed number: no digits after the decimal point");
            return NULL;
        }
        while (tamga_json_peek(p) >= '0' && tamga_json_peek(p) <= '9') {
            p->pos++;
        }
    }

    if (tamga_json_peek(p) == 'e' || tamga_json_peek(p) == 'E') {
        is_integer = false;
        p->pos++;
        if (tamga_json_peek(p) == '+' || tamga_json_peek(p) == '-') {
            p->pos++;
        }
        if (!(tamga_json_peek(p) >= '0' && tamga_json_peek(p) <= '9')) {
            tamga_json_fail(p, "malformed number: no digits in exponent");
            return NULL;
        }
        while (tamga_json_peek(p) >= '0' && tamga_json_peek(p) <= '9') {
            p->pos++;
        }
    }

    token_len = p->pos - start;
    if (token_len > TAMGA_JSON_MAX_NUMBER_CHARS) {
        tamga_json_fail(p, "number literal is unreasonably long");
        return NULL;
    }
    memcpy(token, &p->text[start], token_len);
    token[token_len] = '\0';

    if (is_integer) {
        char *end = NULL;
        long long parsed;
        errno = 0;
        parsed = strtoll(token, &end, 10);
        if (errno == 0 && end != NULL && *end == '\0') {
            return tamga_json_new_int((int64_t)parsed);
        }
        /* Outside int64_t. Carried as a double so the document still parses;
         * precision past 2^53 is lost, which tamga_json_as_int() then refuses
         * rather than reporting a wrong integer. */
    }

    {
        char *end = NULL;
        double parsed;
        errno = 0;
        parsed = strtod(token, &end);
        if (end == NULL || *end != '\0') {
            tamga_json_fail(p, "malformed number");
            return NULL;
        }
        return tamga_json_new_double(parsed);
    }
}

/* --- composites --------------------------------------------------------- */

static TamgaJson *tamga_json_parse_array(TamgaJsonParser *p) {
    TamgaJson *array = tamga_json_new_array();

    if (array == NULL) {
        tamga_json_fail(p, TAMGA_JSON_ERROR_OUT_OF_MEMORY);
        return NULL;
    }
    p->pos++; /* '[' */
    tamga_json_skip_ws(p);

    if (tamga_json_peek(p) == ']') {
        p->pos++;
        return array;
    }

    for (;;) {
        TamgaJson *item = tamga_json_parse_value(p);
        if (item == NULL) {
            tamga_json_free(array);
            return NULL;
        }
        if (!tamga_json_array_append(array, item)) {
            tamga_json_fail(p, TAMGA_JSON_ERROR_OUT_OF_MEMORY);
            tamga_json_free(array);
            return NULL;
        }
        tamga_json_skip_ws(p);
        if (tamga_json_peek(p) == ',') {
            p->pos++;
            tamga_json_skip_ws(p);
            /* A trailing comma lands the next iteration on ']', which
             * tamga_json_parse_value rejects as an unexpected token. */
            continue;
        }
        if (tamga_json_peek(p) == ']') {
            p->pos++;
            return array;
        }
        tamga_json_fail(p, "expected a comma or a closing bracket in array");
        tamga_json_free(array);
        return NULL;
    }
}

static TamgaJson *tamga_json_parse_object(TamgaJsonParser *p) {
    TamgaJson *object = tamga_json_new_object();

    if (object == NULL) {
        tamga_json_fail(p, TAMGA_JSON_ERROR_OUT_OF_MEMORY);
        return NULL;
    }
    p->pos++; /* '{' */
    tamga_json_skip_ws(p);

    if (tamga_json_peek(p) == '}') {
        p->pos++;
        return object;
    }

    for (;;) {
        TamgaBuf key_buf;
        char *key;
        TamgaJson *item;

        tamga_buf_init(&key_buf);
        if (!tamga_json_parse_string_into(p, &key_buf)) {
            tamga_buf_free(&key_buf);
            tamga_json_free(object);
            return NULL;
        }
        key = tamga_buf_detach_string(&key_buf, NULL);
        tamga_buf_free(&key_buf);
        if (key == NULL) {
            /* Either allocation failed, or the key carried an embedded NUL
             * byte. Keys are looked up as C strings, so one is not
             * representable -- rejecting is the fail-closed choice, since
             * silently truncating would make two distinct keys collide. */
            tamga_json_fail(p, "invalid object key");
            tamga_json_free(object);
            return NULL;
        }

        tamga_json_skip_ws(p);
        if (tamga_json_peek(p) != ':') {
            tamga_json_fail(p, "expected a colon after the object key");
            tamga_string_free(key);
            tamga_json_free(object);
            return NULL;
        }
        p->pos++;

        item = tamga_json_parse_value(p);
        if (item == NULL) {
            tamga_string_free(key);
            tamga_json_free(object);
            return NULL;
        }
        if (!tamga_json_object_set(object, key, item)) {
            tamga_json_fail(p, TAMGA_JSON_ERROR_OUT_OF_MEMORY);
            tamga_string_free(key);
            tamga_json_free(object);
            return NULL;
        }
        tamga_string_free(key);

        tamga_json_skip_ws(p);
        if (tamga_json_peek(p) == ',') {
            p->pos++;
            tamga_json_skip_ws(p);
            continue;
        }
        if (tamga_json_peek(p) == '}') {
            p->pos++;
            return object;
        }
        tamga_json_fail(p, "expected a comma or a closing brace in object");
        tamga_json_free(object);
        return NULL;
    }
}

static TamgaJson *tamga_json_parse_value(TamgaJsonParser *p) {
    TamgaJson *value = NULL;
    char c;

    if (p->depth >= TAMGA_JSON_MAX_DEPTH) {
        tamga_json_fail(p, "maximum nesting depth exceeded");
        return NULL;
    }
    p->depth++;

    tamga_json_skip_ws(p);
    c = tamga_json_peek(p);

    switch (c) {
    case '{':
        value = tamga_json_parse_object(p);
        break;
    case '[':
        value = tamga_json_parse_array(p);
        break;
    case '"': {
        TamgaBuf buf;
        tamga_buf_init(&buf);
        if (tamga_json_parse_string_into(p, &buf)) {
            size_t len = 0u;
            /* Detached as raw bytes, not as a C string: a JSON string may
             * legitimately contain a NUL (serde_json accepts one, so the
             * server can sign a payload holding one) and the DOM stores an
             * explicit length alongside the bytes. Object keys are the
             * exception -- see tamga_json_parse_object. */
            unsigned char *raw = tamga_buf_detach(&buf, &len);
            if (raw != NULL) {
                value = tamga_json_new_string((const char *)raw, len);
                tamga_secure_free(raw, len);
            }
        }
        tamga_buf_free(&buf);
        break;
    }
    case 't':
        if (tamga_json_match_literal(p, "true")) {
            value = tamga_json_new_bool(true);
        } else {
            tamga_json_fail(p, "unexpected token");
        }
        break;
    case 'f':
        if (tamga_json_match_literal(p, "false")) {
            value = tamga_json_new_bool(false);
        } else {
            tamga_json_fail(p, "unexpected token");
        }
        break;
    case 'n':
        if (tamga_json_match_literal(p, "null")) {
            value = tamga_json_new_null();
        } else {
            tamga_json_fail(p, "unexpected token");
        }
        break;
    default:
        if (c == '-' || (c >= '0' && c <= '9')) {
            value = tamga_json_parse_number(p);
        } else {
            tamga_json_fail(p, "unexpected token");
        }
        break;
    }

    if (value == NULL && p->error == NULL) {
        tamga_json_fail(p, TAMGA_JSON_ERROR_OUT_OF_MEMORY);
    }
    p->depth--;
    return value;
}

TamgaJson *tamga_json_parse(const char *text, size_t len, const char **error_out) {
    TamgaJsonParser parser;
    TamgaJson *value;

    if (error_out != NULL) {
        *error_out = NULL;
    }
    if (text == NULL) {
        if (error_out != NULL) {
            *error_out = "input is null";
        }
        return NULL;
    }
    if (len > TAMGA_MAX_REASONABLE_LEN) {
        if (error_out != NULL) {
            *error_out = "input exceeds the maximum accepted size";
        }
        return NULL;
    }

    parser.text = text;
    parser.len = len;
    parser.pos = 0u;
    parser.depth = 0u;
    parser.error = NULL;

    value = tamga_json_parse_value(&parser);
    if (value == NULL) {
        if (error_out != NULL) {
            *error_out = (parser.error != NULL) ? parser.error : "malformed JSON";
        }
        return NULL;
    }

    tamga_json_skip_ws(&parser);
    if (!tamga_json_at_end(&parser)) {
        tamga_json_free(value);
        if (error_out != NULL) {
            *error_out = "trailing content after the top-level value";
        }
        return NULL;
    }
    return value;
}
