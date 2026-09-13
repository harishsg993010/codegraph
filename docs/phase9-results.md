# Phase 9 — `diff`: what a change does before it lands

`codegraph diff <source>` compares the tree as it is now with the tree as
the store last indexed it (since Phase 12: with the last commit, when git
knows the tree — see `phase12-results.md`), and says — in graph terms, not line terms —
what changed: every function, method, type, variable, constant and field
that was added, removed, re-signed, redefined or re-bound; which
dependents each change breaks outright; and what each change reaches,
traced through callers, references, imports, subtypes and value flow,
with the relation named on every step. The store is not modified. 327
tests, clippy-clean; one new segment column, readers tolerate its absence.

---

## What it looks like

A three-file Python project; `lib.py` loses `old_api`, gains a parameter
on `run`, changes the value of `MAX_ITEMS` and the body of `helper`:

```
$ codegraph diff .
1 file(s) changed, 0 deleted, 1 neighbour(s) re-extracted
  ~ lib.py

6 change(s), 2 breaking:

  - old_api (lib.py:6) [function] removed — BREAKS 1 dependent(s)
      calls from     process (app.py:3) [function]
    impact (5 symbol(s)):
      called by        process (app.py:3) [function]
        called by        main (app.py:9) [function]
          called by        entry (cli.py:3) [function]
      flows to         run(a) (lib.py:9) [parameter]
        flows to         run (lib.py:9) [function]

  ~ run (lib.py:6) [function] signature (a, b) -> (a, b, c) — BREAKS 1 dependent(s)
      calls from     process (app.py:3) [function]
    impact (3 symbol(s)):
      called by        process (app.py:3) [function]
        called by        main (app.py:9) [function]
          called by        entry (cli.py:3) [function]

  ~ process (app.py:3) [function] bindings changed (-1 calls)
    impact (2 symbol(s)):
      called by        main (app.py:9) [function]
        called by        entry (cli.py:3) [function]

  ~ MAX_ITEMS (lib.py:1) [constant] definition changed
    impact (5 symbol(s)):
      referenced by    process (app.py:3) [function]
        called by        main (app.py:9) [function]
          called by        entry (cli.py:3) [function]
      flows to         run(b) (lib.py:9) [parameter]
        flows to         run (lib.py:9) [function]

  ~ helper (lib.py:3) [function] definition changed
    impact (8 symbol(s)):
      called by        old_api (lib.py:6) [function]
      ...
  + new_api (lib.py:9) [function] added

summary: 6 change(s), 2 breaking, 8 symbol(s) affected
```

`process (app.py:3) bindings changed (-1 calls)` is the other side of the
removal: an importer whose text did not change but whose call no longer
binds. A constant's change is traced through the function that reads it
and on to the parameter its value reaches. `--fail-on-break` exits 2 when
anything breaks, for a pre-commit hook or CI; `--depth` and `-n` size the
trace. The same report is an MCP tool, `diff`, so a model editing a tree
can ask what its edit reaches before it commits.

## How it works

**The change set.** The store holds the tree as last indexed. `diff` copies
the store's segments and manifest — nothing derived — to a scratch
directory and runs the ordinary incremental update there: change detection
by content hash, the changed files re-extracted, their neighbourhood
re-resolved, a delta written to the scratch store. The real store is
untouched (`an_unchanged_tree_has_no_changes_and_the_store_is_untouched`).
Then every symbol in a touched file — changed, deleted, or re-extracted as
a neighbour — is read from both stores by its **key**, which is the same
before and after (that is what keys are for), with three things beside it:

- its **definition hash**: a new `NodeHash` column, FNV-1a over the
  definition's source text with whitespace collapsed, recorded at
  extraction — so a reformat or a move within the file is not a change
  (`reformatting_and_moving_a_definition_is_not_a_change`), and a changed
  literal in a constant is;
- its **parameter list**, in order;
- its **outgoing edges** by relation and target key — calls, references,
  flows, imports, heritage — minus structure (`contains`, CFG, locals).

Key only before → *removed*; only after → *added*; kind differs → *kind*;
parameters differ → *signature*; hash differs → *definition*; edges
differ with the same text → *bindings* (the importer that lost a call).
Blocks, locals and parameters are not changes of their own: a parameter
change is its callable's signature change, a block change is its body's.

**Who breaks.** From the *old* graph, because the dependents that exist
now are the ones the change lands on: for a removed symbol or a changed
kind, every direct dependent along calls, references, imports,
inheritance, implementation, embedding; for a signature change, every
call site. These are listed as `BREAKS`, and they are what
`--fail-on-break` counts.

**What is affected.** A breadth-first trace from the changed symbol, to
`--depth` hops: reverse dependencies along the same relations, plus the
sinks the symbol's *value* flows to along `flows_to` — so a changed
constant reaches the parameter it is passed to, and a function whose
return changed reaches the callers that use the return. Each hit records
its parent and the edge walked, and the report prints the tree. A node
with more than 100 dependents is reported and not expanded; a library
stub is a leaf; 500 hits per change at most. Children are ordered
dependents-first, then by file and line, so the report is the same run
to run.

## Numbers — Gitea

| edit | neighbours re-extracted | time | report |
|---|---|---|---|
| one-line body edit in `modules/util/truncate.go` | 0 | 0.5–0.7 s | 1 change (definition), 1 symbol affected |
| a parameter added to `EllipsisDisplayString` | 628 (every importer of `util`) | 5.7–6.0 s | 1 change (signature), **BREAKS 29 callers**, 266–302 symbols affected within 2 hops (the smaller count is after Phase 10's context-sensitive flows) |

The 0.5 s is the copy of a 94 MB segment plus the update; the 6 s is the
neighbourhood the API change drags in, which is the cost of knowing which
importers re-bound.

## Two things the work fixed

- **`lib.MAX_ITEMS` was a reference to `lib`, not to `MAX_ITEMS`.** A
  member of an import qualifier now resolves to that module's variable
  (`references` from the reader, `flows_to` from its value), which is what
  makes a constant's change traceable at all.
- **Call binding folded case.** Go's exported `EllipsisDisplayString` and
  unexported `ellipsisDisplayString` folded to one name, the call was
  ambiguous, and no `calls` edge existed — so the signature change above
  reported nothing at first. When an exact-case candidate exists, the
  binder now takes it: +1,883 calls bound on Gitea (33.4 %), −1,895
  ambiguous. Call-graph path-traversal findings rose from 16 to 48, all
  test-setup paths (`PrepareTestEnv -> PrepareLFSStorage -> Copy -> Open`)
  that had been missing. `explain` prefers the exact spelling the same way.

## Limits, stated

- A change is what the graph records. A changed string inside a function
  body is a *definition* change of that function (its hash moved) with
  its callers as impact; the graph does not say which line.
- `bindings changed` is reported for neighbours whose edges moved, which
  also happens when a call becomes ambiguous rather than lost.
- "Breaks" is structural: a removed callee, a changed arity. A body change
  that breaks a caller's expectations is impact, not a break — the graph
  cannot know.
- Impact is over the old graph; a symbol added by the change has no
  dependents yet and is listed without a trace.
- The scratch copy is a file copy of the store; on a multi-gigabyte store
  that is the floor of `diff`'s time.
