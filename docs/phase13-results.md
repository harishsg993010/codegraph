# Phase 13 — Rule files: taint questions in YAML

`codegraph audit --rules <file-or-dir>` runs taint questions written in
YAML, in the shape Semgrep users know — `pattern-sources`,
`pattern-sinks`, `pattern-sanitizers`, `pattern-not`, `paths`,
`languages`, `severity`, `metadata` — and a tree's own
`.codegraph-rules.yaml` / `.codegraph-rules/` are read without asking.
Reports are per rule with id, severity and message, as text or JSON;
`--fail-on ERROR` makes it a CI gate. 370 tests, clippy-clean.

---

## What it looks like

```yaml
# .codegraph-rules.yaml
rules:
  - id: go-command-injection
    message: A request value reaches a shell command
    severity: ERROR
    languages: [go]
    metadata: { cwe: CWE-78 }
    paths:
      exclude: [_test.go, tests/integration/]
    pattern-sources:
      - pattern: r              # the *http.Request parameter, by convention
      - pattern: req
      - pattern: "*Request*"
    pattern-sinks:
      - pattern: exec.Command
      - pattern: exec.CommandContext
    pattern-sanitizers:
      - pattern: shellescape.Quote
    pattern-not:
      - pattern: xorm.Exec      # a symbol a pattern picked up that is not meant
```

```
$ codegraph audit ./gitea --kind taint -n 4
rules: 7 from 1 file(s)
taint: a finding is a value from a source reaching a sink's argument. ...

go-command-injection [ERROR] — A request value reaches a shell command
  1845 sources x 1 sinks, 1 sinks searched, 191 finding(s) (120 ms)
  requestJSONResp (external) -> CommandContext (external)  [3 hops, Inferred, unreachable]
      via requestJSONResp -> resp -> ... -> CommandContext
  ...

python-command-injection [ERROR] — Request data reaches a shell or an eval
  0 sources x 0 sinks, 0 sinks searched, 0 finding(s) (37 ms)
```

`--format json` gives one object per rule with its findings (source, sink,
hops, confidence, live, the path); `--fail-on WARNING` exits 1 when any
finding is at that severity or worse. `rules/starter.yaml` in the
repository is the shipped starting point, seven rules over Python, Go,
JavaScript and Java, meant to be copied and edited.

## What a rule says

A `pattern` names a **symbol**, not code — the graph is already the parse.
`Name` is an exact name; `Name*` a prefix; `*Name` a suffix; `*Name*`
anything containing it; `Owner.Name` a member of a type or package
(`os/exec` answers to `exec`; `a::b` splits like `a.b`; `a.b.c.Name`
takes the last owner). The long forms `name:`, `prefix:`, `suffix:`,
`contains:`, `member: [Owner, Name]` and `path:` say the same without the
glob. Names fold case.

In `taint` mode (the default) a source is what *produces* an untrusted
value — a function (its return) or a **parameter** (`request` names every
parameter so called; `handle.request` one function's) — and a sink is
what consumes it: a function or library call, by its arguments. Library
calls are transparent by summary: `r.FormValue(k)` yields `r`'s data, so
the source of a Go handler's input is its request parameter, not
`FormValue`. `mode: callgraph` asks the other question — is there a call
path from a source function to a sink function — and a library stub is a
sink there too, now that calls to library functions are edges.

`languages` and `paths` are tests on the symbol's **file**: a parameter is
judged like its owner (no name index holds parameters; they are found by
a scan, once per rule), a library stub by the file that first mentioned
it — `subprocess.Popen` is Python's because a Python file called it — and
a stub with no file at all passes. `pattern-not` names symbols a pattern
picked up that are not meant; `--exclude PATH` on the command line adds
to every rule's `paths.exclude`.

Two keys tune the search rather than name symbols: `max-hops` (longest
path reported, default 12) and `context-depth` (call sites a value-flow
path may be inside at once before the oldest is forgotten, default 6 —
higher is more precise through deep call chains and slower). Both can be
overridden for every rule at once with `--max-hops` and
`--context-depth` on `audit` (and the MCP tool's arguments of the same
names). The same principle holds elsewhere: `deep` takes `--hops`,
`--seeds`, `--reach-limit` (or `hops:N` etc. in the query), `diff` takes
`--depth`, `--max-fanout`, `--max-impact`, `affected` `--depth`, `path`
`--max-hops`. No search bound is only a constant.

What a rule cannot say, because the analysis does not do it: a pattern
over the text of an expression (`$X = request.args[...]`), a
metavariable, propagators beyond the library summaries. What it says
instead is what the graph knows — which symbols produce untrusted values,
which consume them, which make them safe — and the engine does the rest.

## How it works

`rules.rs` parses (`serde_yaml_ng`, unknown keys refused, every rule
validated at load: an id, at least one source and one sink, known
languages, a well-formed pattern — with the file and rule named in the
error). `Rule::to_spec` builds the existing `TaintSpec`, which gained
`includes` (path) and `languages`, plus a `NameSuffix` matcher. In
`analyse`, path includes/excludes and languages are applied as file
tests in one `keep` pass over sources, sinks and sanitisers, so
parameters and stubs are judged consistently; sources in taint mode add
`parameters_matching`, a scan of parameter rows against the name-style
matchers. `report.rs` runs a list of `RuleSpec`s (rules from files, or
the starter specs wrapped with severity WARNING) and renders text or
JSON; the CLI and the MCP `audit` tool (new `rules` argument) share it.

Two matcher fixes fell out: `Member` accepts a package's last segment as
the owner (`exec.Command` for `os/exec`), and call-graph sinks admit
library stubs.

## Numbers — Gitea

| | |
|---|---|
| `rules/starter.yaml`, 7 rules | Go: command injection 191 findings (sources `r`, `req`, `*Request*`; 1 sink, `exec.CommandContext`), path traversal 43 (5 sinks); the Python, JavaScript and Java rules 0 sources or 0 sinks, as they should on a Go corpus |
| each rule | 20–120 ms after the store is open |
| starter specs (`--presets`, taint mode, field-test excludes) | 361 / 7 / 46 — up from 20 / 7 / 20 in Phase 11 because a source pattern now also names **parameters** (`*request*` matches every `request` parameter), which is what a taint question means by a source |

## Limits, stated

- Sources are named, not typed. The graph does not hold parameter types,
  so "every `*http.Request`" is `r`, `req`, `*Request*` — a convention,
  which finds `IsForkPullRequest` too. `pattern-not` and `paths` narrow
  it; a typed source would need types in the graph.
- A library call named as a source is only a source when its summary
  says its result is external data (`os.Getenv`); a call whose result
  derives from its receiver or arguments (`FormValue`) is transparent,
  and the source is what fed it.
- A rule runs once per corpus; there is no per-file rule, no
  `pattern-inside`, no metavariable binding, no autofix.
- Severity is a label for reporting and `--fail-on`; it does not change
  what is searched.
