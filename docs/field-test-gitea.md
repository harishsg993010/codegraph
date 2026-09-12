# Field test — Gitea

The first run against software nobody wrote for this tool. Gitea: a self-hosted
Git forge, ~3,300 indexable files, Go with a TypeScript frontend, shipped as a
Docker image. Chosen because it is a deployable *system* rather than a library —
it has routers, a permission layer, an ORM, and migrations, so the architectural
and security queries have something real to answer.

## What it found

Seven defects and one missing mechanism, none of which the test suite caught,
because every one of them needed a language the golden corpora do not contain
laid out the way a real repository lays it out.

### 1. A grouped import became one import

Go's `import (...)` block is an `import_declaration` containing one `import_spec`
per line. The config listed **both** node kinds, so the declaration matched too
and fell through to first-named-child text. A five-import file produced six
imports, the extra one being the entire block:

```
"(\n\t\"context\"\n\t\"fmt\"\n\n\t\"code.gitea.io/gitea/models/db\"\n\t...)"
```

Fix: match `import_spec` only.

### 2. An aliased import recorded the alias

`user_model "gitea.dev/models/user"` recorded `user_model`. Go's `import_spec`
has both a `name` field (the alias) and a `path` field (the module), and the
walk's field-priority list tried `name` first.

This is the **same defect as the Python one fixed in Phase 4** — `from typing
import Literal` recording `Literal` — in a language whose field names differ.
The comment warning about it was already in the code, one line above the list
that had the same bug in it again. Ordering `path` before `name` fixes both.

### 3. A dependency list of things that are not dependencies

`package_name` split on `.` as well as `/`. That is right for Python
(`requests.adapters` → `requests`) and wrong for anything whose first path
segment is a **host**: `gitea.dev/models/user` → `gitea`, and `github.com/...`
→ `github`. The top of the dependency list read:

```
gitea    8257 importing files
github   1713 importing files
net      1124 importing files
```

None of those are packages. The dot only separates namespaces when there is no
`/`; when there is one, the specifier is a path and the leading segment may be a
domain. One further split by language: `lodash/fp` is a subpath of `lodash`, but
`net/http` *is* the package — Go has no subpath imports.

### 4. A Go module does not know what directory it is in

Phase 5 added a rule stripping the indexed root's directory name from absolute
self-imports. Go declares its import root in `go.mod`, and it need not resemble
the directory: this checkout sits in `gitea/` and declares `module gitea.dev`.
All **11,979** self-imports were therefore dependencies on a package that does
not exist.

`go.mod`'s module path is now a second import root. The root is a list, not a
string, because the two sources genuinely disagree and both are real.

### 5. Go imports a directory, not a file

The resolver mapped a specifier to at most one file. `import "gitea.dev/modules/setting"`
names *every* `.go` file in `modules/setting/`, and there is no single file to
bind it to — so it resolved to nothing even after the module path was stripped.

Directory expansion is gated on the language rather than made the default:
Python's `import pkg` explicitly does **not** import `pkg`'s submodules, so
expanding there would invent edges. An explicit file still wins over a directory
of the same name.

This one moved the headline number:

| | before | after |
|---|---|---|
| resolved imports | 1,077 | 339,110 |
| **calls bound** | **8.4%** | **32.0%** (31.5% after defect 7) |
| external packages | 1,576 | 747 |

The cost is honest and worth stating: 423k edges for 24k symbols, because
importing a package really does depend on all of its files. A package-node
model — one node per internal directory, `file → package → files` — would be
O(imports + files) instead of O(imports × files) and is the better long-term
shape. It is not built.

### 6. The CLI's own advice did not work

`explain IsUserRepoAdmin` reported the name as ambiguous — correctly, Gitea has
two — and told the user to "qualify it by path". There was no syntax for that.
`path:Name` now works, matching any path suffix.

## Searching it

```
$ codegraph explain <store> models/perm/access/repo_permission.go:IsUserRepoAdmin
IsUserRepoAdmin (models/perm/access/repo_permission.go:529) [function]
  calls (1):      IsUserRealRepoAdmin (models/perm/access/repo_permission.go:534)
  called by (7):  ChangeTitle (services/issue/issue.go:87)
                  CheckPullMergeable (services/pull/check.go:141)
                  createRepositoryInDB (services/repository/create.go:337)  ...
```

`affected --depth 3` on that symbol returns 34 symbols and walks Gitea's actual
layering outward — `models/` → `services/` → `routers/web` and `routers/api`,
plus the integration tests covering them. That is the shape the project is
organised in, recovered from the call graph rather than from paths.

## The dependency view

After the fixes, the list contains only real packages:

```
747 external packages
  github.com/stretchr/testify   1243        net/http    705
  context                       1090        net/url     303
  testing                       1030        xorm.io/builder   175

$ codegraph deps <store> github.com/stretchr/testify
github.com/stretchr/testify: 940 importing files, not reachable from any entrypoint
```

"Not reachable from any entrypoint" for a test framework is the SCA triage
signal working: a CVE in testify does not reach production code here.

## The audit, and what it got wrong

The first run produced 20 command-injection findings. All 20 shared one sink:

```
... -> Exec (models/db/context.go:185)
```

That is **xorm's database `Exec`**, not `os/exec`. The preset matches `exec` by
name, and a name is shared across ecosystems.

There was no way to express the fix. Specs could match a name or a path, never
"this name, except there". `TaintSpec::exclude` now removes matched symbols from
sources and sinks alike, exposed as `audit --exclude <path>`. That removed all
20 — and left four path-traversal findings, which turned out to be a bug of a
different kind.

### 7. A package-qualified call bound to a local function

Three of the four shared a sink, `modules/uri/uri.go:Open`, reached like this:

```
updateGitForPullRequest (services/migrations/gitea_uploader.go:576)
  -> OpenWithClient (modules/uri/uri.go:33)
  -> Open           (modules/uri/uri.go:25)
```

The last hop does not exist. `Open` calls `OpenWithClient`; the reverse edge was
fabricated from line 46 of that file, `os.Open(u.Path)`. Extraction correctly
recorded `callee="Open", receiver="os"`. Resolution tried the receiver rule,
found no *type* named `os`, and fell through to same-file name matching — which
ignores the receiver entirely and bound it to the `Open` defined three lines
above.

A receiver naming an imported package is a **qualifier**, not a value.
`os.Open(x)` calls `os`'s `Open`. The resolver now derives each import's
qualifier and, when a call's receiver matches one:

- if the package is outside the corpus, the call is unresolved — never local;
- if it is inside the corpus, binding is restricted to *that package's* files,
  which is stronger evidence than the name alone.

Not covered: Go aliased imports (`user_model "…/models/user"`), because
extraction records the module path rather than the alias, so the qualifier
`user_model` is not recognised.

This removed **840 wrong call edges** (binding 32.0% → 31.5%) and, with them,
three of the four findings. The resolver's own header says an edge that is wrong
is invisible and poisons everything downstream. This is what that looks like: a
single bad edge produced three security findings and a call cycle between two
functions that call each other once.

```
$ codegraph audit <store> --exclude models/db/ --exclude _test.go --exclude tests/integration/
command-injection: 347 sources x 8 sinks, 95.4% rejected by index, 0 findings (14 ms)
sql-injection:     391 sources x 1 sinks,  70.3% rejected by index, 0 findings (11 ms)
path-traversal:    470 sources x 17 sinks, 94.5% rejected by index, 1 findings (42 ms)
  GetPullRequestFiles (routers/api/v1/repo/pull.go:1492)
    -> readFileName (services/gitdiff/gitdiff.go:1261)  [5 hops, Inferred, unreachable]
```

### No vulnerability was found in Gitea

Stating this plainly, because a findings list invites the opposite reading.
**Zero of these were real.** The one survivor is a false positive too:

- `readFileName(rd *strings.Reader)` parses a filename out of a git diff header.
  It takes a reader, not a path, and opens nothing. It matched
  `contains("readfile")` on the string `readFileName`.
- `GetPullRequestFiles` matched `contains("request")` — because in a Git forge,
  "request" means **pull request**, not HTTP request. Every source in every one
  of these findings matched for that reason.

The presets are Python-shaped word lists. Run against a Go forge, the source
matcher selects the domain vocabulary and the sink matcher selects unrelated
functions sharing a substring. The tool did not find a path traversal; it found
two bugs in itself and a spec that does not fit the corpus.

Two limits this exposed that are **not** fixed:

- **A Go `exec.Command` sink is not expressible at all.** Calls into external
  packages are not materialised as symbols, so there is nothing for a matcher to
  select. Exclusion makes the existing presets honest on Go; it does not make
  them complete. The presets remain Python-shaped (`popen`, `shlex`,
  `secure_filename`).
- **Entrypoint detection found 43 entrypoints, 1.6% of the corpus reachable.**
  Gitea's real entrypoints are route registrations, and name-based detection
  does not see them. Every finding above is therefore marked `unreachable`,
  which is the *detector's* limit rather than a fact about Gitea. This is the
  Phase 4 carry-forward, and this run is the clearest evidence yet that it
  matters: the live/dead split is the single most useful triage signal the tool
  has, and here it is close to uninformative.

## Round two: asking it about access control

Using the tool to answer a real question — how does Gitea authenticate and
authorise? — found six more defects, all in the same place: **Go's method
model**. The walk derives ownership from lexical nesting, which is how Python,
Java and Rust declare methods. Go does not.

### 8. A Go method belonged to no type

`func (p *Permission) IsAdmin()` sits at file top level. The walk saw a
top-level function, so:

- `Permission` had **degree 1** — no link to any of its 18 methods.
- `Permission.IsAdmin` and `Other.IsAdmin` were both just `IsAdmin`, with the
  same scope chain and therefore the same identity up to a disambiguator. The
  walk's own header warns about exactly this: *"the first thing to drift is
  whether a method gets qualified by its class — which silently splits identity
  for that language."* It had drifted.

`LangConfig` now names the field a method's receiver lives in. Where present,
the receiver's type becomes the symbol's scope, and a post-pass emits the
`method` edge — a post-pass because Go permits a method to be declared *above*
its type, so the owner may not exist when the method is seen.

### 9–10. Go types were mis-kinded, and aliases missing entirely

`type_spec` was mapped to `TypeAlias`, so every Go struct and interface reported
as a type alias — and `is_type_like` rejects `TypeAlias`, so receiver-based
binding could never have fired for Go even with ownership. `Def::refined` now
sharpens the kind from the child node (`struct_type` → `Struct`,
`interface_type` → `Interface`).

Separately, `type A = int` is a `type_alias` node, not a `type_spec`, and was
not in the config at all — real Go type aliases were simply not indexed. Found
by writing the test for defect 9.

### 11. `x.F()` inside `F` is not recursion

`services/auth/group.go` holds the authentication chain: `Group.Verify` iterates
its configured methods and calls `method.Verify(...)`. The bare name bound to
the only `Verify` in that file — **itself**. The auth chain read as a function
whose only caller and only callee was itself.

A member call now cannot bind to its own enclosing symbol. Recursion is a bare
`F()`; `x.F()` is a call on something else.

### 12. Import aliases were discarded, and it cost 46% of the call graph

The obvious fix for 11 was stronger: refuse bare-name binding whenever a
receiver is present but untypeable. Measured, that dropped binding from **31.5%
to 17.1%** — `CanWrite` went from 42 callers to 2, `GetDoerRepoPermission` from
92 to 3.

The cause was defect 2's fix over-correcting. Go's `import_spec` carries the
module in `path` and the alias in `name`; defect 2 made `path` win, which was
right for the module, but the alias was then thrown away. Gitea calls
`access_model.GetDoerRepoPermission(...)`, and with `access_model` unknown, that
looks like a method call on an unknown value rather than a package-qualified
call.

`RawImport` now carries the alias, and it takes precedence as the qualifier.
With that, the strict rule was still too blunt — most Go calls are method calls
on locals — so the final rule is narrower and honest: a weakly-typed receiver
still binds by name, but at `Inferred` confidence rather than `Extracted`, and
never to its own caller. Binding returned to 31.5% with the self-loop gone.

### 13. `explain` never showed structure

`explain` printed only call edges. Asking about a *type* and being shown its
call graph hides the thing you asked about. It now lists `members` and
`member of` first.

### Validation

Three independent counts the tool produced were checked against the source and
matched exactly: `RequireUnitReader` 14 route registrations, `RequireUnitWriter`
6, `RequireRepoAdmin` 1, and `reqToken` 188 call sites (189 source matches, one
being the definition). `GetDoerRepoPermission`'s three-way dispatch matched the
function body line for line.

## Round three: `implements` edges for Go interfaces

Round two ended with a real gap: `Group.Verify` dispatches over the eight
authentication methods, and the tool could not show that edge because there was
no `implements` relation for Go. `Relation::Implements` already existed in the
vocabulary and was already in `BLAST_RADIUS` — nothing had ever produced one.

### Why it cannot be read off a declaration

Go has no `implements` keyword. A type satisfies an interface by **having its
methods**, so the edge is not stated anywhere in the source: it has to be
computed by comparing method sets across the whole corpus. Three pieces were
missing.

**Interface method signatures were not extracted at all.** `method_elem` — the
`Name() string` inside an `interface` block — was not in the Go config, so an
interface had no members to compare. It nests inside the `type_spec`, so once
configured the existing scope chain names its interface for free.

**Arity.** Matching on method *names* alone matches far too much. `RawSymbol`
now carries a parameter count where the config asks for one. Counting nodes
would be wrong: Go lets one declaration name several parameters (`f(a, b int)`
is one node holding two names) while an unnamed parameter (`f(int)`) holds none,
so the count is the number of names, or one for an anonymous parameter.

**Embedded interfaces.** `type Logger interface { BaseLogger; LevelLogger }`
states its requirements by reference and has no methods of its own. Ignoring
that does not merely lose information — it makes the interface look *emptier
than it is*, and an under-specified interface matches **more** types. This fails
toward false edges, which is the direction that matters.

A first attempt looked for the embedded name as a direct child of the interface
body and found nothing: Go wraps it in a `type_elem`. The name is a descendant,
not a child.

Embeddings are now expanded by name, and only when the name is unambiguous
corpus-wide. When it cannot be resolved — a generic constraint like
`~int | ~string`, or an embedded `io.Reader` that lives outside the corpus —
the interface is **dropped rather than compared against an incomplete
requirement set**, and counted. On Gitea: 340 edges, 36 interfaces not
comparable.

### What it produces

```
$ codegraph explain <store> services/auth/interface.go:Method
Method (services/auth/interface.go:21) [interface]
  members (2):        Verify, Name
  implemented by (11):
    Basic, OAuth2, Session, SSPI, HTTPSign, ReverseProxy, DeployToken, Group,
    and three package-registry Auth types
```

All 11 were checked against the source: every one has `Name() string` and a
four-argument `Verify`. The three `routers/api/packages/*/auth.go` types are the
interesting ones — the package registries plug into the same authentication
chain, which is not visible from `services/auth` alone.

`Logger` is the embedding case end to end: no methods of its own, expanded to
the eight required by `BaseLogger` + `LevelLogger`, matching exactly one type
(`baseToLogger`), verified method by method against the source.

Because `Implements` is already in `BLAST_RADIUS`, impact analysis now traverses
it: `affected` on the `Method` interface returns all eleven implementations at
depth 1, which it previously could not see at all.

### Stated limits

- **Names and arity, not types.** Parameter and result *types* are not compared.
  Two methods with the same name and parameter count match even if their types
  differ. This is the difference between this and a Go type checker, and it is
  why the edge is `Confidence::Inferred` rather than `Extracted`.
- **Pointer and value receivers are conflated.** Go distinguishes the method set
  of `T` from `*T`; the receiver type is recorded without its pointer, so the
  edge is reported on `T`.
- **Interfaces with unresolvable embeddings produce no edges**, rather than
  partial ones. Counted and reported, not silent.

## Round four: `implements` for Python and TypeScript

Go needed structural matching because satisfaction is never written down.
Python and TypeScript are the opposite problem: they **declare** their
heritage, and nothing was reading it. Before this, the store held no `inherits`
edges at all, in any language — a Python class hierarchy was invisible.

### One generic hook, two very different languages

`LangConfig` gains `supertypes`: node kinds that hold heritage references, and
the relation each implies. Searched no deeper than two levels below the
definition — Python's base list is a direct child, TypeScript nests its clauses
one level inside `class_heritage` — which is shallow enough that a call's
`argument_list` in a class body cannot be mistaken for a base-class list.

```
python:      argument_list       -> inherits
typescript:  extends_clause      -> inherits
             extends_type_clause -> inherits   (interface extending interface)
             implements_clause   -> implements
```

Reading one heritage entry needs care, because two shapes pull in opposite
directions and both occur: a dotted name (`abc.ABC`) means the **last** segment,
while a parameterised one (`Generic[T]`, `Foo<T>`) means the **first**. And
`class C(Base, metaclass=Meta)` names one base, not two — a keyword argument is
a class-creation option.

### Python has no `implements` keyword

`class Redis(Store, Plain)` is one list holding both kinds of relationship.
PEP 544 supplies the rule: a class is a protocol exactly when it lists
`Protocol` itself, and inheriting *from* a protocol does not make the subclass
one. So the distinction is made from the **base**, not the syntax — a base that
is protocol-like (`Protocol`) or abstract (`ABC`, `ABCMeta`) yields `implements`,
and anything else yields `inherits`:

```
Redis  implements  Store   (abc.ABC)
Redis  extends     Plain   (ordinary class)
```

Both from the same declaration line.

### The structural pass had to be fenced off

Running the Go matcher unchanged produced a duplicate: `Impl` appeared twice
under `Greeter`, once from the declared `implements` clause and once from
structural matching, because TypeScript interfaces also have method members.

TypeScript's type system *is* structural, but it has a clause stating the
intent, and matching structurally there would duplicate every declared edge and
add one for every class that happens to share a method name. `LangConfig` now
carries `structural_interfaces`, true only for Go — the language where comparing
method sets is the *only* way to find the edge.

`explain` also split `implements` from `extends`. They answer different
questions and a combined list cannot say which edge is which.

### Validation

On a Python tree, an independent script counted the base references that
resolve within the tree: **27**, exactly matching the tool's `27 resolved`. The
remaining bases are stdlib (`Enum`, `Exception`, `http.client.HTTPConnection`)
and correctly produce no edge rather than binding to a same-named local class.

The vendored `httpx` in that tree gives a real hierarchy to walk end to end:

```
$ codegraph path <store> raw/exceptions.py:ConnectTimeout raw/exceptions.py:HTTPError
4 hops: ConnectTimeout -> TimeoutException -> TransportError -> RequestError -> HTTPError
```

Gitea's Go results are unchanged at 340 structural edges, and its TypeScript
frontend now contributes declared ones.

### Stated limits

- **Only Python, TypeScript and TSX.** JavaScript, Java, C# and Rust all
  declare heritage too and are not wired up; their config entries are empty
  rather than guessed at.
- **A base outside the corpus produces no edge.** Third-party and stdlib bases
  are counted as external, not bound to a same-named local class.
- **Python protocol detection is one level**, which is what PEP 544 specifies:
  a class listing `Protocol` is a protocol; its subclasses are not.

## Numbers

| | |
|---|---|
| files indexed | 3,342 in 2.5 s (**1,357 files/s**) |
| symbols / edges | 24,529 / 425,092 |
| calls bound | 32.2% (from 8.4%) |
| implements edges | 340 (36 interfaces not comparable) |
| store on disk | 18.8 MB (**42.1 B/item**) |
| whole `stats` invocation, cold process | ~210 ms |
| parse failures | 39 files |

The store is 12.7 MB of segment plus a 5.9 MB index. Every read command opens
the mmap'd index; nothing parses on open.

Served over MCP against the same store:

```
initialize -> codegraph 0.1.0, protocol 2025-06-18
explain IsUserRealRepoAdmin -> models/perm/access/repo_permission.go:534, degree 4
```

## What this says about the test suite

Every one of these seven defects was found by *reading output*, not by a failing
test — the same pattern as Phases 3, 4 and 5. The suite tests corpora this
project constructed, and a constructed corpus encodes the assumptions of
whoever constructed it. Five of the seven were Go-specific and one was a
CLI affordance nobody had typed. The last was found only by refusing to believe
a finding and reading the Gitea source it pointed at — which is the check that
should run on every finding a tool like this produces.

All seven now have regression tests. That does not generalise the lesson: the next
language will have its own, and the way to find them is to run the tool on
software written by people who have never heard of it.
