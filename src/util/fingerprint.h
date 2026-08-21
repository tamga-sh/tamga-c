/*
 * fingerprint.h -- canonicalising a machine fingerprint before it is sent.
 *
 * The measured defect this exists to end: every SDK in this family sent the
 * caller's fingerprint string byte-for-byte, and the server stores
 * `fingerprint TEXT NOT NULL` with no length limit, no CHECK and no
 * normalisation, unique per (license_id, fingerprint). So "ABC-123",
 * "abc-123" and " ABC-123 " were three machines on three seats.
 *
 * ⚠️ It deliberately does NOT read hardware identifiers. What identifies a
 * machine is a product decision -- a cloned VM template shares them, a
 * container has none, a replaced motherboard changes them -- and no default is
 * right for both a desktop application and a Kubernetes sidecar. The caller
 * chooses the components; this turns their choice into one stable string.
 *
 * ⚠️ Values are NOT Unicode-normalised, and that is a constraint rather than
 * an oversight. NFC would mean ICU or hand-rolled Unicode tables inside a
 * library whose defining property is having no dependencies, and a rule the
 * eight ports cannot implement identically is worse than no rule at all: it
 * would yield two fingerprints for one machine depending on which SDK the
 * application happened to be written in, silently consuming two seats. Every
 * rule below is ASCII-only for exactly that reason. A caller whose values can
 * arrive in more than one normal form must normalise before calling.
 */
#ifndef TAMGA_UTIL_FINGERPRINT_H
#define TAMGA_UTIL_FINGERPRINT_H

#include <stddef.h>

#include "tamga.h"
#include "tamga_compat.h"

/** The domain-separating prefix, so a future v2 rule cannot collide with v1. */
#define TAMGA_FINGERPRINT_DOMAIN "tamga-fingerprint-v1"

/** U+001F, the ASCII unit separator, emitted as the single byte 0x1f. */
#define TAMGA_FINGERPRINT_SEPARATOR 0x1F

/**
 * Builds the canonical string:
 *
 *   "tamga-fingerprint-v1" <US> join(<US>, sort_bytewise(["label=trimmed"]))
 *
 * On TAMGA_OK, `*out_canonical` receives an owned NUL-terminated string
 * released with tamga_string_free(). Nothing is written on any other outcome.
 */
TAMGA_NODISCARD TamgaErrorCode tamga_fingerprint_build_canonical(const char *const *labels,
                                                                 const char *const *values,
                                                                 size_t count,
                                                                 char **out_canonical);

#endif /* TAMGA_UTIL_FINGERPRINT_H */
