# AI assistance log

This log records project assistance requests, outcomes, identified flaws, and corrections. Some older entries were carried forward from the existing project log; where the original full prompt or transcript is unavailable, that is stated rather than reconstructed. The workspace has no Git metadata, so no commit links could be verified.

## 2026-11-05 — Initialize project context

- **Prompt:** `/init`
- **AI output summary:** Identified the FastAPI/PostgreSQL app and inspected its entry point, schema, and tests.
- **Specific flaw identified:** None; this was context setup, not a bug investigation.
- **Correction made:** None; no application change was made for this prompt.
- **Files reviewed:** [main.py](main.py), [schema.sql](schema.sql), [test_main.py](test_main.py).
- **Commit link:** None; no commit is available in this workspace.

## 2026-11-05 — Interactive UI

- **Prompt:** “add features and make better and interactive UI”
- **AI output summary:** Added a responsive authentication and document workspace UI, including search and document actions.
- **Specific flaw identified:** The initial sharing interface was account-ID-based and did not reflect the effective `EDIT` grant consistently (as recorded in the existing project log).
- **Correction made:** The interface was aligned with named email grants and API-returned access; authorization remains server-side.
- **Files recorded:** [static/app.js](static/app.js), [static/index.html](static/index.html), [static/styles.css](static/styles.css).
- **Commit link:** None; no commit is available in this workspace.

## 2026-11-05 — Document authorization

- **Prompt:** The existing project log records a request to restrict document access to owners and explicitly granted users, make revocation effective, audit denied attempts, and add adversarial tests. Original full wording is unavailable.
- **AI output summary:** Added route tests for document access, permission changes, account deactivation, and denied operations.
- **Specific flaw identified:** Admin had an implicit document-access bypass in list, search, or download paths (as recorded in the existing project log).
- **Correction made:** Document operations were scoped to current ownership or grants; Admin remains subject to document authorization.
- **Files recorded:** [test_main.py](test_main.py), [main.py](main.py).
- **Commit link:** None; no commit is available in this workspace.

## 2026-11-05 — Audit integrity

- **Prompt:** The existing project log records a request to make audit history resistant to quiet edits/deletions and document design limits. Original full wording is unavailable.
- **AI output summary:** Added audit hash-chain setup and a verification helper.
- **Specific flaw identified:** The initial chain trigger could read an uninitialized head without serializing concurrent first inserts; the prior deletion path also changed historic audit rows (as recorded in the existing project log).
- **Correction made:** The chain-head row is created before it is locked, and historic audit rows are not changed by document deletion. The database-owner limitation is documented.
- **Files recorded:** [schema.sql](schema.sql), [verify_audit.py](verify_audit.py), [THREATS.md](THREATS.md).
- **Verification note:** The existing log states PostgreSQL execution was unavailable at that time; it does not establish a PostgreSQL integration test result.
- **Commit link:** None; no commit is available in this workspace.

## 2026-11-05 — Immediate account revocation

- **Prompt:** The existing project log records a request to make account deactivation immediate and provide an Admin flow. Original full wording is unavailable.
- **AI output summary:** Added database-backed account-status checks, status management, and a token-reuse test.
- **Specific flaw identified:** JWT role/status claims alone would continue to authorize a stale token after deactivation; the existing local database also needed the `is_active` schema update (as recorded in the existing project log).
- **Correction made:** Each authenticated request reloads current user role and active status from PostgreSQL; schema setup includes `is_active`.
- **Files recorded:** [main.py](main.py), [test_main.py](test_main.py), [schema.sql](schema.sql), [README.md](README.md).
- **Commit link:** None; no commit is available in this workspace.

## 2026-11-06 — Admin overview

- **Prompt:** “Improve the existing TrustVault Admin Dashboard.” The request specified live user/role counts and recent audit activity, while explicitly prohibiting automatic Admin access to private documents.
- **AI output summary:** Added an Admin-only database-backed dashboard response and a matching overview UI with statistics, recent activity, and navigation to user management and audit logs.
- **Specific flaw identified:** The Admin's document view appeared empty because the Admin had no document grants; treating this as a reason to grant broad access would violate the document authorization policy.
- **Correction made:** Added the separate Admin overview and retained the existing owner/grant checks for document APIs. Owner and Viewer access to Admin APIs remains denied by role checks.
- **Files recorded:** [main.py](main.py), [static/app.js](static/app.js), [static/index.html](static/index.html), [static/styles.css](static/styles.css), [test_main.py](test_main.py).
- **Verification note:** The prior project context records 22 passing tests for that implementation; this is historical and is not a result of the current documentation changes.
- **Commit link:** None; no commit is available in this workspace.
