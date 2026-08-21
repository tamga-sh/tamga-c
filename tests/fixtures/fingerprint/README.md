# Fingerprint canonicalisation vectors

Input components and their canonical string and digest, used by
`tests/unit/fingerprint_test.c`.

## The rule

```
fingerprint = lowercase_hex( SHA-256( UTF-8( canonical ) ) )      // 64 chars
canonical   = "tamga-fingerprint-v1" <US>
              join(<US>, sort_bytewise([label "=" trimmed_value]))
```

`<US>` is U+001F, the ASCII unit separator. **In this file it is written as the
literal four-character text `<US>` so the JSON stays diffable and greppable**;
the byte that gets hashed is the single `0x1f`. `expand_separator()` in the
test does the substitution — an implementation that hashed the four characters
would reproduce none of the digests.

## The defect these exist to pin

All eight SDKs sent the caller's fingerprint string byte for byte, and the
server stores `fingerprint TEXT NOT NULL` — no length limit, no CHECK, no
normalisation — unique per `(license_id, fingerprint)`. So `"ABC-123"`,
`"abc-123"` and `" ABC-123 "` were three machines on three seats.

## The three that matter most

Each is a **pair**, and the pair is the point: a table of expected digests
passes for an implementation that is consistently wrong in the same way the
table was generated wrong, while an equality between two of the
implementation's own outputs does not.

| invariant | vectors | relation |
|---|---|---|
| order-independence | `two_sorted`, `two_unsorted` | must be **equal** |
| whitespace-trimming | `whitespace_trimmed`, `single` | must be **equal** |
| case preservation | `case_preserved`, `single` | must **differ** |

`non_ascii_value` pins that non-ASCII passes through as its UTF-8 bytes —
neither transcoded, escaped nor normalised.

It does **not** pin the sort's signedness, and no vector can. A hand-rolled
comparison written as `a[i] - b[i]` over plain `char` orders every byte above
`0x7F` as negative on a signed-char target, but the label rules make that
unreachable: labels are unique and ASCII-printable excluding `=`, so the first
differing byte between any two valid components always falls inside the label
region or at the `=` boundary, and is always ASCII. Both the signed comparison
and the comparator's prefix tiebreak were confirmed unreachable by mutation —
each leaves every vector here green. They are pinned directly instead, against
the static comparator, in `tests/unit/fingerprint_sort_test.c`.

(For the record: `memcmp`, `strcmp` and `strncmp` are all *specified* to compare
as `unsigned char` — C11 7.24.4p1 — so the library functions are safe on any
target. Only a hand-rolled loop is not. This SDK uses `memcmp`.)

**Bytewise order and code-point order are the same thing**, by UTF-8's
construction, so there is deliberately no vector for that distinction: such a
test cannot fail. The two orderings that genuinely diverge, and that these
vectors also cannot separate, are sorting by the label alone instead of the
whole `label=value` component, and folding case in the comparator. Both are
covered by dedicated tests in `tests/unit/fingerprint_test.c` — the labels here
are all lowercase and none is a prefix of another, so both wrong rules produce
this exact table.

## Why the rejections are rejections

Eight cases under `rejected` — empty label, duplicate label, `=` in a label,
the separator in either half, a control character in a value, no components,
and a non-ASCII label.

Every one must be an error and **never a repair**. Stripping a control
character or picking one of two values for a repeated label maps two different
inputs onto one canonical string, which is two machines sharing one seat — the
mirror image of the defect above.

## Why there is no Unicode normalisation

Deliberate, and a constraint rather than an oversight. NFC would mean ICU or
hand-rolled Unicode tables inside a library whose defining property is having
no dependencies, and a rule the eight ports cannot implement identically is
worse than no rule: it would yield two fingerprints for one machine depending
on which SDK the application was written in, silently consuming two seats.
Everything above is ASCII-only for exactly that reason, which is what makes it
implementable here with the C standard library plus the SHA-256 already in the
tree. A caller whose values can arrive in more than one normal form must
normalise before calling.

## Provenance

**Not generated here.** Produced by an independent SHA-256 implementation, not
by any SDK in this family — a fixture an SDK produced can only prove that SDK
agrees with itself, which is exactly how a two-year machine-file bug survived
in this repository with CI green throughout (see
`../server-machine-files/README.md`). Do not regenerate these with this
library. This copy is byte-identical to the upstream file.
