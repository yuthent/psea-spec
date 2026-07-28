# Repository rules for automated tooling

Applies to any AI assistant or automated agent making changes in this
repository, in addition to [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Commit trailers

Commits to this repository MUST NOT carry AI-attribution trailers
(Co-Authored-By naming a model, Claude-Session or equivalent session links).
This is a public IETF specification repository and the draft has one author.
Suppress the trailer default rather than stripping it afterwards — a rewrite is
only available before a push.
