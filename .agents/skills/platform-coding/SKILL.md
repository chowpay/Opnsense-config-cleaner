---
name: platform-coding
description: Focused implementation and verification for an assigned coding task.
---

# Platform coding workflow

Inspect the current code and acceptance criteria before editing. Choose the
smallest complete change that satisfies the assignment and reuse existing
sanitization functions. Add tests for observable behavior and failure cases;
tests must use synthetic data only. Run the relevant focused checks and record
their actual outcomes. Check the final diff for scope, secrets and unintended
changes. Report the exact resulting commit and remaining uncertainty. An
independent reviewer evaluates the committed revision; the developer does not
approve or merge its own work.
