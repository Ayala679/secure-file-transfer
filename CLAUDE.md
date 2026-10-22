# Defensive Systems Programming – final project (20937, 2026c)

Encrypted file-transfer system: Python server + C++20 client.
The user writes in Hebrew – answer in Hebrew.

Read and follow these before any work:
- @INSTRUCTIONS.md – binding rules from the assignment (protocol must not change).
- @ARCHITECTURE.md – numbered design decisions (D1, D2, ...). Update when a decision changes.
- @PLAN.md – day-by-day task plan; tick `[x]` only after the task's check passes.

Work in small steps; each step ends with a passing check before moving on.

## Code style – strict
- NO comments at all in code – not even short ones, no docstrings. The user asked for this explicitly and firmly. Only exception: lint directives like `# noqa: BLE001`.
- Code must not look AI-generated: no docstrings on trivial functions, no step-by-step narration, no banners/separators, no emoji, no restating the code. Clear names instead of comments.
- Keep chat answers short too.
