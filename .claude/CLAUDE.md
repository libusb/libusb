# Project Memory

## Commit Authorship

Every commit in this repository must be authored by a human (the user). Claude/AI must not be set as the commit author.

At the end of every commit message, include an explicit attribution trailer indicating which AI model assisted, in this format:

```
Assisted-by: AGENT_NAME:MODEL_VERSION
```

For example: `Assisted-by: claude-code:claude-opus-4-7`

This applies to all commits, including those created via automation or agent workflows.

## Commit generation

No commit should be signed-off by AI agent or os. Only human can sign-off their commits with their own certificate.

## Branch Naming

- Do not prefix branches with `claude/`, `ai/`, `bot/`, or any agent-derived namespace.
- Do not append auto-generated suffixes (random IDs, timestamps, session hashes) unless genuinely required to disambiguate.
- Branch names should be explicit and brief about what is being done or asked — e.g. `add-commit-attribution`, `fix-win-hang`, etc.
- Prefer kebab-case.

## PR description content

The `Assisted-by` attribution should be included in the PR description, but no link to the session itself should be included, as it is not publicly accesible.

When a PR fixes an issue or relates/replaces to another issue, the PR description should include a reference to the issue number after main description but before `Assisted-by:` attribution, e.g. `Fixes: #123` or `Closes: #124`
