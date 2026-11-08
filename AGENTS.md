# Contribution Guidelines for AI Coding Agents

These are the canonical contribution and commit rules for this repository. They apply to
**every** AI coding agent used on this project (OpenAI Codex, Cursor, GitHub Copilot, Claude
Code, Gemini CLI, and others) and to any automation acting on a contributor's behalf.

This file (`AGENTS.md`) is the single source of truth. Most agents read it natively; the few
that use a dedicated file load these same rules from here — `.claude/CLAUDE.md` and `GEMINI.md`
import it, and `.github/copilot-instructions.md` points to it — so there is only ever one copy
to maintain.

## Communication

Use ASD-STE100 Simplified Technical English for all user-facing messages in
this repository. Put the result first. Use short, direct sentences. Use one
term for one concept. Avoid idioms, slang, and ambiguous pronouns. Explain a
technical term when the user might not know it.

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

Always use the most specific model variant available, not a shorter model-family name.
When combining or preserving trailers, including during squash merges, deduplicate
attributions for the same agent and keep only its most specific model variant. For
example, if `Assisted-by: Codex:GPT-5.6 Sol` applies, do not also add the less-specific
`Assisted-by: Codex:GPT-5` trailer. Multiple `Assisted-by` trailers are appropriate for
different agents, but not merely for different specificity levels of the same agent.

This applies to all commits, including those created via automation or agent workflows.

## Commit generation

No commit should be signed-off by an AI agent or OS. Only a human can sign-off their commits
with their own certificate.

## Branch Naming

- Do not prefix branches with `claude/`, `copilot/`, `codex/`, `cursor/`, `ai/`, `bot/`, or any agent-derived namespace.
- Do not append auto-generated suffixes (random IDs, timestamps, session hashes) unless genuinely required to disambiguate.
- Branch names should be explicit and brief about what is being done or asked — e.g. `add-commit-attribution`, `fix-win-hang`, etc.
- Prefer kebab-case.

## Primary C Build and Other Compilation Contexts

libusb is a C project whose primary use and build context is as a C library compiled with a
C compiler. Its C sources are sometimes used in other contexts, including being compiled with
a C++ compiler.

When a change is required only for a non-primary context, both the commit message and the PR
description must:

- Explicitly name the affected context, for example, "building libusb's C sources as C++."
- Explain why the change is needed in that context.
- State whether the primary C library build is unaffected.

Do not describe a context-specific change as a general C or libusb build fix unless it also
affects the primary C library build.

## Public API and ABI Compatibility

`libusb/libusb.h` is the installed public API header and must be treated as a
compatibility contract for existing source and binary users.

- Do not change the type, calling convention, parameters, return value, or
  linkage of an existing public function to fix an internal implementation
  issue, compiler warning, or refactor. Even an ABI-equivalent type change can
  break source users, including code with explicitly typed function pointers.
- Do not remove or incompatibly change public declarations, constants, enum
  values, structure layouts, or other ABI-visible definitions.
- Additive public API changes require explicit task scope and a compatibility
  review. Documentation-only changes remain permitted.
- If a fix appears to require a breaking change in `libusb/libusb.h`, preserve
  the existing interface and ask a maintainer for direction instead of making
  the API or ABI change.

## Comments

An implementation comment should explain information that the code alone does
not express, such as a constraint, invariant, concurrency assumption, platform
or protocol quirk, or why an obvious alternative was rejected. Do not add
comments that only restate the implementation in English.

- Keep implementation comments concise. Use one line when practical, and match
  the touched file's existing comment format and density. Do not comment every
  statement or block.
- File or module introductions, Doxygen API documentation, function contract
  comments, and concise section labels are permitted. State the contract,
  context, and edge cases instead of narrating the implementation.
- Example and tutorial code may use short step comments when they help readers
  follow the intended use of the API.
- Do not remove or rewrite comments outside the change's scope only to enforce
  these rules.

## Concise Writing

Signal over noise in all agent-written prose -- documentation, commit messages,
PR descriptions, and README sections. Every word must carry information.

- No filler ("It's important to note", "Additionally") and no restating what
  the code or the previous paragraph already says.
- Use active voice and present tense: "Run tests", not "You should run the
  tests".
- Prefer bullets to paragraphs unless prose is genuinely clearer.
- Assume a competent reader. Expand only on genuinely non-obvious trade-offs
  and edge cases.

## PR description content

The `Assisted-by` attribution should be included in the PR description, but no link to the
session itself should be included, as it is not publicly accessible.

When a PR fixes an issue or relates to / replaces another issue, the PR description should
include a reference to the issue number after the main description but before the
`Assisted-by:` attribution, e.g. `Fixes: #123` or `Closes: #124`.
