# Phase 10 — the stated limits, addressed

Phases 7–9 each ended with a list of what the analysis did not do. This
phase takes the list as the specification: context sensitivity across
calls, alias analysis, field sensitivity on locals, predicates beyond
literals, extensible library summaries, and a flow-sensitive stored view
of locals. Each is done to the point where the remaining gap is a
fundamental one — stated below, per item, with what "fundamental" means.
337 tests, clippy-clean, no format change.

The headline number: dataflow findings on Gitea with the field-test
excludes, **3,297 / 655 / 12,548 → 284 / 7 / 46** (command injection /
SQL injection / path traversal), and each spec runs in 80–300 ms. The
call-graph audit is unchanged (26 findings without excludes, 58 with the
exact-case binder from Phase 9). Base + deltas against a fresh index: still
identical edge sets, 0 dangling.

---

## 1. Context sensitivity across calls

*Was:* a callee's `param -> return` summary was one edge for every caller;
a value entering `ident` from `a` left it into `b`'s result. Library stubs
were the exception, by call-site tag.

*Now:* every edge into a callee's parameter carries the call site it
enters on and every edge out of a callee's return the site it leaves on —
the same `"<leave>><enter>"` tag stubs had, now on resolved calls too. The
backward search keeps the sites it is inside as a **stack**: walking
backwards through a return pushes the site, walking backwards through an
argument must pop the same one — matched like parentheses. A path that
begins inside a callee has an empty stack and may leave towards any
caller, which is the sound reading of "the sink is reachable from this
parameter". The stack is bounded (6); past that the oldest site is
forgotten, which only admits more. External data (`os.Getenv`,
`fgets`) leaves a stub on a site nothing enters on, so a library read is
a source and never a conduit. Arrivals at a node are grouped by enter
site once, so a visit to a function every file calls costs the edges of
one call.

This is what moved the numbers: −91 % / −99 % / −98 %, and the searches
got faster, because a hub function's parameter now admits one caller's
edges, not all of them. Test: `a_value_leaves_a_callee_only_at_the_call_site_it_entered`
(one level and two levels of nesting).

*Remaining gap:* call-string sensitivity to depth 6, not full CFL
reachability with unbounded stacks; recursion deeper than 6 frames
re-admits callers. A package used as a value is no longer a flow node at
all (it was a conduit between every writer and reader of `os.*`).

## 2. Field sensitivity on locals

*Was:* `a.x = v` tainted `a`; `sink(a.y)` saw `v`.

*Now:* a member or subscript path on a local is its own definition site,
`a.x`, `a[]`, `a.b.c`. A read of `a.y` sees definitions of `a.y`, of
every prefix (`a` — a whole-object assignment) and of every extension
(`a.y.z`); a strong definition of `a` kills `a` and everything under it,
never its prefixes; a whole read of `a` sees every field. So `a.x = t;
sink1(a.y)` does not carry `t`, `sink2(a)` does, and `a = fresh();
sink3(a.x)` carries nothing (`a_field_is_its_own_value_and_the_whole_object_carries_every_field`,
ten languages). Indices are folded (`a[i]` and `a[j]` are one path `a[]`).
Field paths are not stored rows — they fold to their root local in the
CFG and local views.

*Remaining gap:* `self.x` and receiver fields keep their existing
per-field treatment; fields of non-locals are field-insensitive; array
indices are not distinguished.

## 3. Aliasing

*Was:* `p = &x; *p = v` did not taint `x`; `b = a; b.x = v` did not taint
`a.x`.

*Now:* a flow-insensitive **may-alias class** per body, by union-find:
`p = &x` / `&mut x` / `ref x` joins `p` and `x`; in the languages where a
copy shares the object — Python, Ruby, JavaScript, TypeScript, Java, C#,
Go — so does `b = a` between locals; in C, C++ and Rust a plain copy is a
copy. A write *through* one member of a class — `*p = v`, `p.f = v`,
`p[i] = v`, a mutating method (`same.append(t)`), a by-reference call —
is a weak write to the same path of every member; a read through one
reads every member. Classes are "may": a write through one member is a
weak definition of the others, which is the sound direction. Atoms about
an aliased local are invalidated by that weak definition like any other.
Tests: `a_copy_shares_the_object_where_the_language_says_so`,
`a_write_through_a_pointer_writes_the_pointee` (C, C++, Go, Rust),
`mutation_through_a_method_reaches_every_alias`.

*Remaining gap:* this is intraprocedural and flow-insensitive; two
parameters that alias, aliasing through a container (`list[0] = &x`), and
aliasing established in a callee are not seen. A points-to analysis over
the whole program is a different engine.

## 4. Predicates

*Was:* only a local against a literal; a three-atom integer
contradiction was missed.

*Now:*
- **Two subjects compared**: `a == b`, `a != b`, `a < b`, `a <= b` (and
  `>`/`>=` by swapping) are atoms; `a == b` then `a != b` prunes, `a < b`
  then `a >= b` prunes, `a < b` then `a <= b` does not. `a == b` also
  joins the two subjects' integer intervals and literal equalities.
- **Pure terms** as subjects: a call to a side-effect-free predicate from
  a fixed list (`len`, `isEmpty`, `is_some`, `startsWith`, `contains`,
  `isinstance`, … 73 names) on a local, with literal arguments, is a
  subject whose text is its identity: `s.isEmpty()` then `!s.isEmpty()`
  prunes; `len(items) > 0` then `len(items) == 0` prunes; an arbitrary
  call still establishes nothing. A pure predicate also no longer counts
  as a possible write to its argument in the by-reference languages.
- **Exact multi-atom check**: a set of three or more atoms is decided
  exactly (`n >= 7 ∧ n <= 7 ∧ n != 7`), memoised per set.
- Atoms are invalidated by definitions of any local a subject mentions,
  and by field writes under it.

And a bug the new atoms surfaced: the capped atom sets are not monotone
under the fixpoint's join (a set that fills up keeps whichever atoms came
first, and the order can differ round to round), so the reaching-
definitions iteration could oscillate — one Gitea function ran the full
10,000-round limit, 9.6 s. After 48 rounds without convergence the pass
now **widens**: every atom is dropped and it finishes as plain reaching
definitions, sound and convergent. One function in 15,659 on Gitea.
Tests: `two_subjects_compared_are_an_atom`,
`pure_predicates_are_subjects_and_other_calls_are_not`,
`three_atom_intervals_are_decided_exactly`.

*Remaining gap:* no arithmetic (`n + 1 > m`), no relation between a
truthiness atom and an equality atom, no reasoning across a call that
returns a boolean the caller then tests, no theory beyond intervals and
equalities. These are what an SMT solver would add; nothing here is one.

## 5. Library summaries

*Was:* ~1,150 built-in entries; an unknown name kept the sound default.

*Now:* ~1,400 built-in entries (Go `net/http`, `database/sql`, `os/exec`,
`regexp`, hashing; Python `subprocess`, `requests`, `flask`, `django`,
`pickle`, `yaml`; JavaScript `fs`, `child_process`, `crypto`, `axios`,
Express responses, lodash; Java `Files`, `StringUtils`,
`StringEscapeUtils`, JDBC, streams) and a **user table**:
`.codegraph-summaries.json` at the source root, a JSON array of `{"name",
"shape", optional "lang", "qualifier", "method": true}` entries, loaded
at every index and consulted before the built-ins. Adding a library is
one line per function.

*Remaining gap:* an unknown name still keeps the sound default; the
table is data, and the world's libraries are not enumerable. Method
shapes are by name and are the union over the common types with the
name.

## 6. Locals, flow-sensitively

*Was:* one row per local name, and `local_flow` edges that merged every
definition: `x = a; x = b; sink(x)` showed `a` and `b` into `x`, `x` into
`sink`.

*Now:* the rows are still one per name — the store does not grow — but
every `local_flow` edge carries its definitions: `origin -> local` says
which line assigned it, `local -> sink` lists the lines of every
definition that reaches that read. `explain f.x` prints them:

```
  assigned from (3):
    [parameter] a (f.py:1)  at line 2
    [parameter] b (f.py:1)  at line 4
    [parameter] a (f.py:1)  at line 7
  read into (3):
    [function external] sink1 (external)  (definition at line 2)
    [function external] sink2 (external)  (definition at line 4)
    [function external] sink3 (external)  (definitions at lines 4,7)
```

`sink3` after `x = b; if a: x = a` sees lines 4 and 7, not 2. Test:
`local_flow_edges_carry_definition_lines`.

## Numbers — Gitea

| | Phase 9 | now |
|---|---|---|
| full index | 19–24 s | 14–17 s (extract 4.6 s, resolve 5.7 s, compact 2.9 s, index 0.6 s) |
| `diff`, one-line body edit / API change | 0.5 s / 6.0 s | 0.7 s / 5.7 s (628 importers re-extracted; 266 symbols affected within 2 hops, was 302 — the flows through the change are now the matched ones) |
| rows / edges | 360k / 2.04 M | 352k / 2.18 M |
| `flows_to` | 686k | 818k (field paths make more, finer facts) |
| store | 94 + 34 MB | 121 + 36 MB |
| dataflow findings (excludes) | 3,297 / 655 / 12,548 | **284 / 7 / 46** |
| dataflow time per spec | 0.3–2.0 s | 0.08–0.3 s |
| call-graph findings (no excludes) | 58 | 58 |
| body edit / equivalence | 0.4 s / identical | 0.6 s / identical, 0 dangling |

The remaining command-injection findings are of the shape
`GetUnmergedPullRequest -> issueID -> Exec`: a corpus function's return
reaching a database `Exec` by name. That is a name-matched sink, the
Phase 9 carry-forward that still stands.

## What is still true

Every item above is sound by the same rule as before — the analysis may
report a flow that cannot happen and does not drop one that can — and
every item is bounded: a call-string depth, a may-alias class, a fixed
predicate list, a widened fixpoint, a summary table. The bounds are the
limits now, and each is a knob rather than a design absence.
