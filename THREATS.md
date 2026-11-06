# TrustVault threat model

## Scope and assets

TrustVault is a FastAPI application backed by PostgreSQL, with a browser frontend and document files stored under the local `uploads/` directory. This threat model reflects the current implementation; it is not a security certification or deployment review.

Assets to protect:

- Document contents, filenames, metadata, ownership, and access grants.
- User identities, password hashes, account roles, and active status.
- JWT signing secret and issued bearer tokens.
- Audit-log records and their hash-chain state.
- PostgreSQL credentials, database records, and uploaded files.
- The availability and integrity of the application and its backups.

Threat actors include unauthenticated internet users, authenticated users attempting to exceed their role or grants, compromised user accounts, malicious uploaders, a host or database administrator, and attackers with access to deployment secrets or storage. A PostgreSQL owner or superuser is treated as a privileged actor who can defeat database-local controls.

## Authentication and account security

| Threat | Mitigations implemented | Remaining risks |
|---|---|---|
| Guessing credentials or enumerating accounts | Passwords are hashed using `pwdlib`'s recommended Argon2 configuration. Login failures return a generic invalid-credentials message and are audited. Registration validates email and requires at least eight password characters. | No MFA, login rate limiting, lockout, email verification, or abuse monitoring. The minimum password length alone does not ensure a strong password. |
| Public user self-assigns a privileged role | Registration always assigns `viewer`; role input is not used to assign an account role. Admin/Owner accounts are provisioned outside public registration. | The security of privileged account provisioning and database credentials remains an operational responsibility. |
| Disabled user retains access | Each authenticated request reloads active status and role from PostgreSQL; an inactive account is rejected even if its JWT has not expired. Admin cannot deactivate their own account through the status endpoint. | Database outages affect authentication availability. No separate token-revocation list exists. |
| Password reset bypasses normal controls | The application does not expose a public password-reset route. | `reset_password.py` directly updates a database password and does not create an audit event. Restrict its use to controlled local administration; it is not a production recovery workflow. |

## Unauthorized document access and permission escalation

| Threat | Mitigations implemented | Remaining risks |
|---|---|---|
| Admin, Owner, or Viewer accesses a document without authorization | Document queries and operations scope access to the caller's ownership or current `READ`/`EDIT` grant. Admin role alone does not grant document access. | Keep authorization tests and a real-PostgreSQL role matrix current for every route. |
| `READ` grant is used to modify or share a document | `READ` permits list/search/download. `EDIT` adds metadata update and file replacement. Sharing and deletion require ownership. The server enforces these rules regardless of UI state. | Deployment changes or new endpoints must preserve the same checks. |
| Revoked grant remains effective through stale client state | Grants are fetched from the database for protected document operations; access changes apply on the next request. | A previously downloaded copy cannot be recalled. |
| Identifier tampering or role manipulation escalates access | SQL parameters are used for application queries; server-side ownership/grant checks are applied. The JWT role is checked against the current database role. | SQL injection and authorization safety still depend on maintaining parameterized queries and reviewing new code paths. |
| A user gains an unintended grant | Owners grant `READ` or `EDIT` to an active account selected by email; only owners can manage grants for their documents. | Email verification and external guest identity controls are not implemented. Mistyped recipient addresses remain a human risk. |

## JWT and browser session risks

- Login issues a signed JWT using HS256 with a 30-minute expiration. The application rejects a missing or shorter-than-32-character `SECRET_KEY`.
- Protected requests use bearer authentication. The database is consulted for current account status and role; the token is not treated as an enduring authorization grant.
- The browser stores the token in `sessionStorage`, which limits persistence to the browser tab session but remains readable by same-origin JavaScript.
- The frontend sends the bearer token in the `Authorization` header. This avoids ambient-cookie CSRF behavior but does not protect against cross-site scripting that can read the token.
- Changing `SECRET_KEY` invalidates existing tokens; automated key rotation is not implemented. Protect the secret with a deployment secret manager and use HTTPS.
- No Content Security Policy or broader security-header configuration is implemented in this project.

## File upload and storage threats

Implemented checks include a 5 MiB read limit, extension allowlist (`.pdf`, `.doc`, `.docx`, `.txt`, `.png`, `.jpg`, `.jpeg`), non-empty file/category checks, randomized storage names, authenticated download routes, and path validation. Uploads are stored on disk and are not mounted as public static files.

Remaining risks:

- Extension checks do not verify file content or detect malware. No antivirus, sandboxing, or content-disarm process exists.
- Uploaded files are not encrypted at rest by the application. Filesystem encryption and restrictive permissions must be configured by the operator.
- The current storage is local to the application host and uses a relative `uploads/` directory. It needs persistent storage and backup; multiple instances need a shared storage strategy.
- No document versioning or file-recovery feature exists. Deleting a document can remove its stored file.
- A file that a user has already downloaded cannot be revoked.

## Audit-log tampering and coverage

Audit events are recorded for application operations including login attempts, registration, upload and file replacement, metadata changes, sharing/revocation, account-status changes, and document deletion. The schema defines an insert hash-chain trigger, serializes chain-head updates, rejects update/delete/truncate mutations, and revokes those mutations from `PUBLIC`. `verify_audit.py` checks the stored chain.

Limitations:

- The application role must not own the schema/tables and must not receive audit-row update/delete/truncate privileges. Apply and verify least-privilege database grants during deployment.
- The chain has no independent external/WORM anchor. A PostgreSQL owner or superuser can alter triggers, rows, or hashes and rewrite the chain.
- Some failures rejected before a route runs, dependency-level role denials, network errors, or database outages may not produce an audit event. Audit coverage is not a complete forensic record.
- Audit details may contain operational information. Restrict access to Admin users and avoid adding secrets or unnecessary personal data to audit details.

## Database and deployment security

The application uses parameterized SQL and validates current roles/grants in the API. `schema.sql` configures the schema and audit triggers. The application does not itself enforce PostgreSQL network isolation, TLS, backups, encryption at rest, secret rotation, or privilege provisioning.

For deployment, use a private PostgreSQL network, a dedicated non-owner/non-superuser application account with only required table privileges, encrypted database connections where supported, a managed secret store, HTTPS, restricted filesystem permissions, and tested backup/restore procedures. Do not expose `.env`, the database port, or `uploads/` through a public web root. The application's PostgreSQL connection configuration does not explicitly set TLS options; configure and verify the database/server/client transport policy for the selected environment.

## Known limitations and remaining risks

- No MFA, rate limiting, account lockout, email verification, or automated abuse monitoring.
- No CSP/security-header policy or dedicated browser security test suite.
- No upload content inspection or malware scanning.
- No application-managed at-rest encryption, file versioning, or disaster recovery.
- No independent audit-chain anchor or complete audit coverage guarantee.
- No production deployment manifest, CI pipeline, or configured hosting environment is included.

These are known gaps, not implemented controls. Review them against the intended deployment's data sensitivity and threat model before exposing the service publicly.
