# Phase 11 — `deep`: search by what code is connected to

`codegraph deep <store> <terms and filters>` finds code by what it *does*
and what it is *next to*, not only by what it is called. A term matches a
symbol's name and path by subword, and the inside of a function: its
locals and parameters, the callees it calls, the variables it reads, and
the conditions it branches on. Matches spread along calls, references and
value flow, so the function that connects two terms scores for both even
when neither word is in its name. Filters narrow by structure — kind,
path, who it calls, who calls it, what it reads, what its value reaches —
and every hit says why it is there. 346 tests, clippy-clean, no format
change.

---

## What it looks like

Gitea, 3,342 files. Where is the upload size limit enforced?

```
$ codegraph deep ./gitea upload size limit -n 3
3 hit(s) for terms ["upload", "size", "limit"] (246 ms)

  3.38  CheckSizeQuotaExceeded (services/packages/packages.go:362) [function]
          condition `totalSize+uploadSize > setting.Packages.LimitTotalOwnerSize` matches 'upload'
          name matches 'size'
          condition `setting.Packages.LimitTotalOwnerSize > -1` matches 'limit'

  3.38  NewLimitedUploaderKnownSize (services/attachment/attachment.go:48) [function]
          name matches 'upload'
          name matches 'size'
          name matches 'limit'

  3.12  TestPackageQuota (tests/integration/api_packages_test.go:514) [function]
          local `uploadPackage` matches 'upload'
          local `limitSizeGeneric` matches 'size'
          local `limitSizeGeneric` matches 'limit'
```

`CheckSizeQuotaExceeded` has one of the three words in its name. A
substring search for `upload` returns 540 symbols; this returns the
function whose *branch conditions* are the size check, first.

A phrase is a run of subwords in any spelling code uses:

```
$ codegraph deep ./gitea "rate limit" kind:function -n 3
  0.95  IsRateLimitError (services/migrations/error.go:17) [function]
          name matches 'rate limit'
  0.80  handleMigrateError (routers/api/v1/repo/migrate.go:219) [function]
          condition `case: migrations.IsRateLimitError(err)` matches 'rate limit'
  0.44  MigratePost (routers/web/repo/migrate.go:155) [function]
          calls handleMigrateError
```

Structure alone is a query. Which functions in the tests directory call
the library function `exec.Command`? Which parameters in `routers/` have a
value that reaches `CommandContext`?

```
$ codegraph deep ./gitea ssh key calls:Command
  1.65  run (models/asymkey/ssh_key_test.go:452) [function]
          path matches 'ssh'
          path matches 'key'
          calls Command

$ codegraph deep ./gitea flows-to:CommandContext kind:parameter in:routers/ -n 2
  0.16  toPullLink(ctx) (routers/web/feed/convert.go:40) [parameter]
          its value reaches CommandContext
  0.14  toIssueLink(ctx) (routers/web/feed/convert.go:36) [parameter]
          its value reaches CommandContext
```

Every query above runs in 60–450 ms on the 352k-symbol store. The same
search is the MCP tool `deep_search`.

## How it works

**Terms.** Each term is scored against every symbol independently, then
the scores are combined. A term matches a name exactly (1.0), as a whole
subword — `upload` in `MaxUploadSize`, `HTTPServer` splits to `http`,
`server` (0.9) — as a prefix (0.8), a subword prefix (0.7) or a substring
(0.55); a file stem counts 0.6 of that, a directory 0.3. A phrase (`"rate
limit"`) is a run of adjacent subwords, or the collapsed / snake / kebab
spelling. Then the inside of every callable: a **local or parameter**
whose name matches credits its owner (×0.75), a **branch condition**
whose text matches credits the function that branches on it (0.7). The
condition text is the predicate the stored CFG already carries on its
`succeeds` edges, so this is a read of the graph, not of the source.

**Spreading.** The strongest matches for a term (up to 400) pass half
their score to each graph neighbour along calls, references, value flow,
membership and heritage, and a quarter two hops out; a node keeps the best
share it is offered and the reason names the match it came from, from the
neighbour's point of view (`calls handleMigrateError`, `referenced by
runServ`, `its value reaches CommandContext`). Three things do not spread:
hubs (the index's degree cutoff — everything is next to `Sprintf`), library
stubs (a stub is not a connection between its callers), and structure
between a matched member and its owner. A neighbour with more than 50
edges takes a share scaled by 50/degree, so one match does not make a
logger relevant.

**Combining.** A symbol's score is the sum of its per-term scores, plus
0.5 for every term beyond the first it has any credit for, plus a small
degree term as the tie-break. Two terms met beats one met twice over. A
term a hit has nothing for is shown as `(nothing for 'x')`, so a
one-term hit on a three-term query reads as what it is.

**Filters.** `kind:`, `in:` are tests on the hit. `calls:`, `called-by:`,
`references:`, `referenced-by:` are one-edge tests against the symbols the
name resolves to — bare or qualified (`exec.Command` is the member
`Command` of the package `os/exec`), stubs included, with a substring
search as the fallback. `reaches:` (call graph), `flows-to:` and
`flows-from:` (data flow) are reachability: the target set is expanded
backwards or forwards over the relation once, to 500k nodes, and the hit
must be in the set. With no terms at all, every symbol that passes the
filters is a hit, ranked by degree. Blocks, locals, files and packages are
never results; parameters are results only when `kind:parameter` asks
for them.

## Two things the graph was missing

Both surfaced by writing the filter tests, both fixed in the extractor
and the resolver rather than in the search:

- **A read only in a condition was not a reference.** `if size >
  MAX_UPLOAD_BYTES:` produced a predicate atom and a CFG edge, but no
  `references` edge from the function to the constant, because the
  scanner recorded uses only where a value flowed somewhere — an
  assignment, an argument, a return. A bare read is now an op of its own
  (`Op::Read`): a use with no sink. Gitea: 29,784 → 32,610 `references`
  edges (+9.5 %). An import statement naming the symbol is excluded — that
  is the `imports_from` edge, not a read
  (`a_read_only_in_a_condition_is_a_reference_in_every_language`, all
  eleven languages).
- **Calls to library functions had no `calls` edge.** A call the binder
  could not resolve had a stub for its *value flow* but no call edge, so
  "who calls `exec.Command`" had no answer and `calls:Command` matched
  nothing. Every unresolved, unambiguous call now has a `calls` edge to
  its stub, flagged external (`edge_flags::EXTERNAL`, 92,075 on Gitea, the
  count of unresolved calls). The call-graph questions answer as before —
  a stub reaches nothing — and `explain` lists them under `calls` as
  `[function external]`. `diff` ignores external targets when it compares
  a symbol's bindings, so a call that *stops* resolving still reads as
  `-1 calls`. Two consequences had to be handled: a store with deltas can
  now hold a stub whose only caller was re-indexed away, which the view
  hides (an external row with no edges left is not canonical); and
  `explain exec.Command` resolves — a package answers to its last segment.

## Numbers — Gitea

| | before | after |
|---|---|---|
| full index | 13.7–17 s | 15.7–16.8 s |
| symbols / edges | 351,862 / 2,183,313 | 352,264 / 2,299,027 |
| `calls` edges | 55,525 | 147,600 (92,075 to stubs) |
| `references` edges | 29,784 | 32,610 |
| base + deltas vs fresh (`codegraph-verify diff`) | identical, 0 dangling | identical, 0 dangling |
| call-graph audit, field-test excludes | 0 / 10 / 20 | 0 / 10 / 20 |
| dataflow audit, field-test excludes | 20 / 7 / 20 | 20 / 7 / 20 |
| `deep`, three terms | — | 190–450 ms |
| `deep`, filters only | — | 60–400 ms |

The audit numbers are the same before and after, as they must be: the
new edges are external `calls` (which taint mode does not walk through a
stub) and `references` (which no taint mode walks). They are lower than the
figures the Phase 10 document and the README gave (284 / 7 / 46): those
do not reproduce against the committed Phase 10 build on the same
checkout — the sink count differs (54 then, 60 now), so they were taken
against a different spec or store state. The README now carries the
numbers this build produces.

## Limits, stated

- A term is matched to names, paths, locals, parameters, callees,
  referenced variables and stored branch predicates — not to string
  literals, comments or arbitrary expressions inside a body. A function
  whose only connection to `upload` is a log message is not found.
- Spreading is two hops from the top 400 matches per term and never
  through a hub or a stub; a connection longer than that, or only through
  `Sprintf`, is not seen. Both are the reason the search is fast.
- Scores are a ranking, not a probability; the reasons are the thing to
  read. A three-term query on a corpus where two of the terms are common
  can rank a well-named two-term hit above the right three-term one when
  the third term matched only a directory.
- Reachability filters resolve their target once, over the whole graph,
  capped at 500k nodes; on a store larger than that the filter is
  partial and says nothing about it yet.
