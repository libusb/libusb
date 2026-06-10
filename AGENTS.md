# Contribution Guidelines for AI Coding Agents

These are the canonical contribution and commit rules for this repository. They apply to
**every** AI coding agent used on this project (OpenAI Codex, Cursor, GitHub Copilot, Claude
Code, Gemini CLI, and others) and to any automation acting on a contributor's behalf.

This file (`AGENTS.md`) is the single source of truth. Most agents read it natively; the few
that use a dedicated file load these same rules from here — `.claude/CLAUDE.md` and `GEMINI.md`
import it, and `.github/copilot-instructions.md` points to it — so there is only ever one copy
to maintain.

## Commit Authorship

Every commit in this repository must be authored by a human (the contributor). No AI agent
(Codex, Cursor, GitHub Copilot, Claude, Gemini, or any other) may be set as the commit author.

At the end of every commit message, include an explicit attribution trailer indicating which
AI model assisted, in this format:

```
Assisted-by: AGENT_NAME:MODEL_VERSION
```

For example: `Assisted-by: claude-code:claude-opus-4-7` or
`Assisted-by: github-copilot:MODEL_VERSION`.

This applies to all commits, including those created via automation or agent workflows.

## Commit generation

No commit should be signed-off by an AI agent or OS. Only a human can sign-off their commits
with their own certificate.

## Branch Naming

- Do not prefix branches with `claude/`, `copilot/`, `codex/`, `cursor/`, `ai/`, `bot/`, or any agent-derived namespace.
- Do not append auto-generated suffixes (random IDs, timestamps, session hashes) unless genuinely required to disambiguate.
- Branch names should be explicit and brief about what is being done or asked — e.g. `add-commit-attribution`, `fix-win-hang`, etc.
- Prefer kebab-case.

## PR description content

The `Assisted-by` attribution should be included in the PR description, but no link to the
session itself should be included, as it is not publicly accessible.

When a PR fixes an issue or relates to / replaces another issue, the PR description should
include a reference to the issue number after the main description but before the
`Assisted-by:` attribution, e.g. `Fixes: #123` or `Closes: #124`.
