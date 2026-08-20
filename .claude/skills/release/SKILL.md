---
name: release
description: >-
  Cut a release: size a SemVer bump from the diff, promote the CHANGELOG, commit and tag.
  Use when asked to release, tag a version, bump or decide a version number, publish to NuGet,
  or promote the Unreleased section of a CHANGELOG; do NOT use to push a tag, to cut a
  prerelease (CI publishes those per commit), or in a repo whose publish is not tag-triggered.
user-invocable: true
auto-trigger: false
trigger_keywords:
  - release
  - cut a release
  - tag a version
  - bump the version
  - version number
  - semver
  - changelog
  - nuget
  - publish package
  - major minor patch
---

# /release — Cut a Release

## Orientation

**Use when:**
- Asked to cut, tag, or publish a release
- Asked what version number a set of changes warrants
- Commits have landed on `main` and the `## [Unreleased]` changelog section needs promoting

**Do NOT use when:**
- The ask is to push an existing tag. This skill never pushes; it hands the command over.
- A prerelease is wanted. CI publishes `-ci.N` builds per commit automatically; they are never cut by hand.
- The repo publishes from something other than a `v*` tag on `main`. Say so and stop.

**What this skill needs:**
- A .NET repo with packages under `src/`, GitVersion computing the version in CI, a `v*` tag on `main`
  triggering the NuGet publish, and `CHANGELOG.md` in Keep a Changelog format
- A clean working tree on `main`, and `gh` authenticated for the CI check
- Everything else project-specific (which projects pack, the repo URL, the prerelease label) is derived
  by the steps below, never hardcoded

An argument like `2.1.1` or `v2.1.1` pins the version. Without one, suggest a number and get agreement
before writing anything.

## Why the approval gate exists

Pushing a tag publishes to nuget.org, and **NuGet packages are immutable**. A wrong version number cannot
be recalled, only superseded. Never run `git push` in this skill. Stop at the tag and ask.

**No exceptions.** Not for a version the user named themselves, not for a patch, not for a docs-only
release, not when they said "go ahead" before the number existed.

| Rationalization | Reality |
|---|---|
| "They already approved the push earlier" | They approved a version that had not been computed yet. Approval attaches to a specific number on a specific commit. Re-ask. |
| "A wrong tag is fine, I can delete and re-tag" | True locally, false once pushed. The package is on nuget.org within minutes and cannot be replaced. |
| "CI is green on main" | Green on *a* commit. Compare SHAs against `HEAD` or it means nothing. |
| "Push the branch now, tag right after" | That race publishes a prerelease. `--atomic`, or not at all. |
| "The commit messages make the bump obvious" | Subjects describe intent. Only the diff decides. |
| "Nothing consumer-facing changed, but bump anyway" | Then there is nothing to release. Say so. |
| "Just force-push to tidy up the release commit" | Origin may already hold a published tag. Never force-push `main` here. |

### Red flags, stop and re-read

- About to type `git push` anywhere in this skill
- Sizing the version from commit subjects rather than from `git diff`
- Reading a version number without having run `git fetch origin --tags` first
- Reusing an approval given before step 4 settled the number
- Writing a CHANGELOG entry that names no replacement for something removed

## Protocol

### Step 1: VERIFY — Preconditions

```bash
git rev-parse --abbrev-ref HEAD     # must be main
git status --porcelain              # must be empty
git fetch origin --tags             # --tags is not optional, see below
git status -sb                      # must not be behind origin/main
```

**Fetch tags, not just commits.** GitVersion reads local tags only. A tag that exists on origin but not
locally makes it fall back to an older one and compute a version that looks plausible and is wrong, with
no error to warn you.

IF `main` is behind, rebase onto `origin/main` before going further. Never force-push over it: by the
time a release commit exists, origin may already hold a published tag.

Confirm CI is green **on the commit being released**, not merely on `main`. The latest run is usually
for an older commit, so compare the SHAs rather than trusting the green tick.

**Ask the publishing workflow, not the newest run.** A repo usually has several workflows, and a green
CodeQL or lint run says nothing about whether the package builds. Find the one that publishes, then
filter to it:

```bash
grep -l 'nuget push' .github/workflows/*.yml     # the publishing workflow
git rev-parse HEAD
gh run list --branch main --workflow <thatFile> --limit 1 --json headSha,conclusion,displayTitle,workflowName
```

IF `headSha` matches `HEAD` AND `conclusion` is `success`, CI covers what you are releasing.

ELSE it does not, and the usual cause is commits sitting unpushed. CI cannot be made to cover those
without pushing, which is the very thing awaiting approval, so verify locally instead:

```bash
dotnet test -c Debug
```

Add `dotnet pack -c Debug` when the diff touches any packable `.csproj`, `Directory.Build.props`, or
another file that feeds package metadata, since that metadata is not exercised by a test run.

A red CI run on a matching SHA, or any local failure, is a blocker. Raise it and stop. Report which of
the two paths was used and say so precisely; "CI is green" and "I built it locally" are different claims.

### Step 2: FIND — The last stable version

Prerelease tags are never cut by hand here, but filter anyway so the command stays correct:

```bash
git tag -l 'v*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1
```

Output: `<lastTag>`, used by every step below.

### Step 3: DIFF — Decide what actually ships

**Read the diff, not the commit messages.** Commit subjects describe intent; the package contents decide
the version number.

```bash
git diff --stat <lastTag>..HEAD
git diff <lastTag>..HEAD -- src/
```

Work out which projects actually produce packages rather than assuming every project under `src/` does:

```bash
grep -rlE '<IsPackable>\s*true|<GeneratePackageOnBuild>\s*true|<PackageId>' src/ --include='*.csproj'
grep -nE '<IsPackable>|<PackageReadmeFile>|<PackageId>' Directory.Build.props 2>/dev/null
```

`Directory.Build.props` can make everything under `src/` packable at once, in which case the individual
`.csproj` files say nothing and the whole directory ships.

What reaches consumers:

| Path | Ships? | Notes |
|---|---|---|
| `src/<Package>/**/*.cs` | Yes | The assembly and its XML docs |
| `src/<Package>/<Package>.csproj`, `Directory.Build.props` | Metadata only | `Description`, `PackageTags` and dependency version ranges are consumer-facing |
| `README.md` | Yes, if `PackageReadmeFile` is set | It is then the nuget.org landing page |
| `tests/**`, `.github/**`, `AGENTS.md`, `CLAUDE.md`, `global.json`, `*.slnx` | No | Repo-only, never a reason to release |

A diff touching nothing in the "Yes" rows means there is nothing to release. Say so rather than
manufacturing a version.

In a multi-package repo the version is still solution-wide: GitVersion stamps every package from the one
tag, so size the bump from the largest change across all of them, and name in the changelog which package
each entry belongs to when it is not obvious.

### Step 4: SIZE — Suggest the number

The project follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Its rules 6 to 8
are the whole test, and they turn on one question: what happened to the public API?

| Bump | Spec rule | When |
|---|---|---|
| Major | 8, backward incompatible change to the public API | A public type or member was removed, renamed, or had its signature changed. Also a raised minimum dependency version, since the dependency range is part of the contract consumers resolve against. |
| Minor | 7, new backward compatible functionality | A new public type or member was added, with everything existing still working. |
| Patch | 6, backward compatible bug fixes | An internal fix with no public API change. |

**Below 1.0.0, rule 4 applies instead:** anything may change at any time and the public API is not
considered stable. Check what the repo's own README or `CHANGELOG.md` intro promises, and follow that.
The common convention, and the one to assume absent a statement otherwise, is that a breaking change
takes the minor and everything else takes the patch, so `0.x` never bumps to `1.0.0` by accident.

Subclassers count. Rule 1 requires the public API be "precise and comprehensive", so where a public type
has `virtual` or `protected` members, a change to one of those signatures is backward incompatible even
when callers never see it. Check for prior releases in `CHANGELOG.md` that treated it that way and cite
them as precedent.

**Docs-only and metadata-only releases are outside the spec.** Rule 6 scopes patch to bug fixes, and
nothing in SemVer 2.0.0 or its FAQ covers a release that changes only the README or `<Description>`.
Patch is the usual convention, on the reasoning that the API is unchanged and consumers can skip the
upgrade freely. Say that it is a convention rather than citing a rule that does not exist, and say
plainly in the changelog that no code changed.

State the recommendation with the evidence for it, then confirm before writing. Use `AskUserQuestion`
when there is a genuine fork (for example, whether a docs-only change is worth a release at all), but
not to re-ask something already settled earlier in the conversation.

### Step 5: PROMOTE — The CHANGELOG entry

`CHANGELOG.md` follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/). Changes accumulate
under `## [Unreleased]` as they land, so releasing **promotes that section** rather than writing a new
one. Get the date from the machine, do not assume it:

```bash
date +%Y-%m-%d
```

Rename the heading to `## [<version>] - <YYYY-MM-DD>`, leave a fresh empty `## [Unreleased]` above it,
and update the link references at the bottom of the file. Take the repo URL from the remote rather than
typing it, and copy the exact shape of the existing lines:

```bash
git remote get-url origin        # strip any .git suffix
tail -5 CHANGELOG.md
```

```markdown
[Unreleased]: <repoUrl>/compare/v<version>...HEAD
[<version>]: <repoUrl>/compare/v<previous>...v<version>
```

IF `[Unreleased]` is empty because the changes landed before this convention, write the entries now from
the diff in step 3.

Rules, from the spec and from how the file already reads:

- **Group under the spec's six headings**, in this order where present: `### Added`, `### Changed`,
  `### Deprecated`, `### Removed`, `### Fixed`, `### Security`. Omit any that are empty. No other
  headings.
- **Terse.** One line per change. The grouping already says what kind of change it is, so do not restate
  it in the text.
- **Keep a Changelog has no breaking category.** Mark breaking items inline inside `### Changed` or
  `### Removed` with `**Breaking:**`, or `**Breaking for subclasses:**` when only overriders are
  affected.
- **Anything deprecated or removed must point somewhere.** Name the replacement API, or link the upstream
  doc that explains the move, so the reader is not left to search. Do not log a removal without an exit
  route. Per SemVer rule 9 and the SemVer FAQ, a removal should have been preceded by a `### Deprecated`
  entry in an earlier release; if it was not, say so in the entry.
- **Dates are ISO 8601** (`YYYY-MM-DD`), as the spec requires.
- **No prerelease entries.** Per-commit prereleases (`-ci.*`, or whatever label `GitVersion.yml` sets)
  publish automatically and are out of scope.

### Step 6: COMMIT — Commit and tag

**Re-check origin first.** Step 1 ran before the version was agreed and the changelog written, and step 7
then waits on a human. Origin can move across either gap, and it has:

```bash
git fetch origin --tags
git status -sb
git ls-remote --tags origin "v<version>"
```

Three ways this comes back bad, all recoverable only before you commit:

- **Behind `origin/main`:** rebase onto it, then redo steps 3 and 4. The diff you sized the version from
  is stale.
- **`v<version>` already exists on origin:** that version is published and immutable. Stop. Pick the next
  number, or determine whether a release is still needed at all.
- **Diverged, with your own earlier release commit upstream:** rebase onto `origin/main` and let git drop
  the duplicate. Do not force-push, and do not move a tag whose package is already on nuget.org.

Then commit, since the tag must land on the commit that contains the CHANGELOG entry:

```bash
git add CHANGELOG.md
git commit -m "Release <version>"
git tag v<version>
```

The `v` prefix is required. GitVersion resolves the tag on `HEAD` to exactly that stable version;
without a tag it produces a prerelease instead. Confirm it before handing over the push:

```bash
dotnet-gitversion | grep '"SemVer"'
```

A prerelease suffix here means the tag is not on `HEAD`, or was never fetched. IF `dotnet-gitversion` is
not installed locally, either install it (`dotnet tool install -g gitversion.tool`, matching the
`versionSpec` the CI workflow pins) or fall back to `git describe --tags --exact-match`, which confirms
the tag is on `HEAD` but not what GitVersion will compute from it.

### Step 7: STOP — Ask for approval

Report the tag, the version, and the CHANGELOG entry. Then ask for approval to push, and hand over the
command rather than running it:

```bash
git push --atomic origin main v<version>
```

`--atomic` matters. Both refs update in one transaction, so the tag is present when either workflow run
reaches its GitVersion step and both compute the stable number. Pushing them separately is a race: if
the branch run gets there first it builds a prerelease and publishes one nobody asked for. Two runs are
expected either way, and `dotnet nuget push --skip-duplicate` absorbs the second.

**The user may run it themselves rather than replying.** Origin then moves with nothing in this session
recording it, so any later step must re-read git state instead of trusting what was true when you asked.
Assume nothing about `origin/main` across an approval gate.

IF the user declines, leave the commit and tag in place. Both are local and reversible
(`git tag -d v<version>`, `git reset --hard <commit>`). Say that plainly so the state is clear.

One trap when undoing: `git tag -d` on a tag that also exists on origin removes it only locally, and
GitVersion then silently reports a lower version derived from an older tag. Restore it with
`git fetch origin --tags` before reading any version number.

## Quality Gates

- [ ] `git status --porcelain` was empty and `HEAD` was on `main` before anything was written
- [ ] `git fetch origin --tags` ran before every version number was read
- [ ] CI status was compared by SHA against `git rev-parse HEAD`, or `dotnet test -c Debug` passed locally
- [ ] Which of those two paths was used is stated in the report, not blurred
- [ ] The bump was justified from `git diff <lastTag>..HEAD`, with the deciding files named
- [ ] The bump follows SemVer rule 4 where the version is below 1.0.0, and rules 6 to 8 above it
- [ ] The user agreed the number before `CHANGELOG.md` was edited
- [ ] `## [Unreleased]` was promoted, a fresh empty one left above it, and both link references updated
- [ ] Every `### Removed` and `### Deprecated` entry names a replacement or links an explanation
- [ ] The date came from `date +%Y-%m-%d`
- [ ] `git ls-remote --tags origin "v<version>"` returned nothing before the commit was made
- [ ] The tag is `v`-prefixed and sits on the commit containing the CHANGELOG entry
- [ ] `dotnet-gitversion` reports the stable version with no prerelease suffix
- [ ] No `git push` was run by this skill

## Exit Protocol

```
RELEASE PREPARED — NOT PUSHED

Version: <version>   (was <lastTag>)
Bump: <major|minor|patch> — <one-line reason, citing the deciding files>
Commit: <sha> "Release <version>"
Tag: v<version>
GitVersion reports: <SemVer>

Verified by: <CI run <id> on matching SHA | local dotnet test -c Debug>

CHANGELOG entry:
  <the promoted section, verbatim>

To publish, run:
  git push --atomic origin main v<version>

Not pushed. Both the commit and the tag are local and reversible:
  git tag -d v<version> && git reset --hard <sha-before>
```
