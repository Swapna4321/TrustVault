# TrustVault

TrustVault is a FastAPI and PostgreSQL document-sharing application with a static HTML, CSS, and JavaScript frontend. Access to documents is enforced by the API on every request; hiding a control in the browser does not grant or revoke access.

## Features

- Registration creates Viewer accounts; Admin and Owner roles are provisioned separately.
- JWT bearer authentication, Argon2 password hashing, and active-account checks.
- Document upload, search, download, metadata updates, replacement, and owner-only deletion.
- Per-document `READ` and `EDIT` grants. A `READ` grant allows listing, searching, and downloading; `EDIT` also allows metadata changes and file replacement.
- Admin overview, user status management, and audit-log views. Admin status does not grant access to private documents.
- Database-backed audit records with a hash chain and an audit verification helper.

## Technology

- Python 3.10+
- FastAPI, Uvicorn, Pydantic
- PostgreSQL with `pgcrypto`
- Psycopg 3
- Static HTML, CSS, and JavaScript
- Pytest and HTTPX for automated tests

## Project structure

```text
TrustVault/
├── main.py                    # FastAPI application and API routes
├── schema.sql                 # PostgreSQL schema and audit-chain setup
├── requirements.txt           # Runtime and test dependencies
├── test_main.py               # Automated tests
├── API.md                     # API routes and authorization matrix
├── README.md
├── THREATS.md
├── PROMPTS.md
├── .env.example               # Safe environment-variable template
├── .gitignore
├── seed_demo.py               # Optional demo-account/sample-data setup
├── seed_sample_documents.py   # Optional sample document helper
├── verify_audit.py            # Audit-chain verification helper
├── db_test.py                 # Database connection helper
├── check_password.py          # Local password-check helper
├── reset_password.py         # Password-change helper requiring the current password
└── static/
    ├── index.html
    ├── app.js
    └── styles.css
```

`uploads/` is local document storage and is excluded from Git. Preserve and back it up if it contains user documents. There is no separate `templates/` or migrations directory; `schema.sql` creates the current schema and applies the included schema updates. The local virtual environment and Python caches are not application source.

## Local installation

Prerequisites: Python 3.10 or later, PostgreSQL, and the PostgreSQL command-line client (`psql`).

From the project directory, create and activate a virtual environment and install dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` locally. Set the database connection values and generate a unique signing key of at least 32 characters:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Never commit `.env`; `.env.example` contains placeholders only.

## PostgreSQL setup

Create a dedicated database and login. Use a unique database password and keep this login a non-superuser:

```sql
CREATE ROLE trustvault_app LOGIN PASSWORD 'replace-with-a-unique-secret';
CREATE DATABASE trustvault_db OWNER trustvault_app;
```

Set `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, and `DB_PORT` in `.env` to match your local setup. As a PostgreSQL administrator, apply the schema; this schema setup requires permission to install `pgcrypto`:

```powershell
psql -U postgres -d trustvault_db -f schema.sql
```

Grant the runtime role only the application table permissions it needs. Run these statements as a database administrator:

```sql
GRANT USAGE ON SCHEMA public TO trustvault_app;
GRANT SELECT, INSERT, UPDATE ON users TO trustvault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON documents TO trustvault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON permissions TO trustvault_app;
GRANT SELECT, INSERT ON audit_logs TO trustvault_app;
GRANT SELECT ON audit_chain_state TO trustvault_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO trustvault_app;
```

Do not grant the runtime role ownership, superuser status, or `UPDATE`, `DELETE`, or `TRUNCATE` access to `audit_logs`. The audit trigger updates its chain state through a `SECURITY DEFINER` function. Review and apply equivalent least-privilege grants if your deployment uses a different database role or schema.

## Demo accounts

Demo data is optional and should only be created in a disposable development database. `seed_demo.py` creates the three demo accounts and a sample document with a Viewer `READ` grant. It refuses to modify accounts or existing permission grants; if a configured demo email already exists (including on a rerun), it stops and you must use dedicated demo emails. It does not reactivate or change existing accounts. Do not run demo seeders against production or user data.

Set local values for `SEED_ADMIN_PASSWORD`, `SEED_OWNER_PASSWORD`, and `SEED_VIEWER_PASSWORD` in `.env`. The default emails are `admin.test@example.com`, `owner.test@example.com`, and `viewer.test@example.com`; optional `SEED_*_EMAIL` variables can override them. Use only dedicated demo addresses. Then run:

```powershell
python seed_demo.py
```

The script does not print passwords. Registration through the application creates Viewer accounts only; it is not an Admin/Owner provisioning mechanism. Never use real or reused passwords for demo accounts.

`seed_sample_documents.py` is also optional. Set `SEED_OWNER_EMAIL` and `SEED_VIEWER_EMAIL` to the dedicated active demo accounts before running it. It does not choose users automatically, and it leaves any existing permission grants unchanged.

`reset_password.py` is a password-change helper for an active account: it requires that account's current password before changing it.

## Run locally

From the project root, with the virtual environment active and PostgreSQL available:

```powershell
uvicorn main:app --reload
```

Open the application at `http://127.0.0.1:8000/app`. Interactive API documentation is at `http://127.0.0.1:8000/docs`; the health endpoint is `http://127.0.0.1:8000/health`. See [API.md](API.md) for routes and authorization rules.

## Tests and audit verification

Run the automated suite:

```powershell
python -m pytest -q
```

Most tests use isolated database fakes. The Owner and Admin database integration tests need the schema applied, matching seeded users, and `TEST_OWNER_PASSWORD` / `TEST_ADMIN_PASSWORD` set to the corresponding local account passwords. Otherwise, those tests are skipped. Do not point tests at a production database.

To verify the stored audit chain against the current database:

```powershell
python verify_audit.py
```

This helper reads the configured database. It does not create demo data.

## Deployment guidance

No hosting provider, public deployment URL, container manifest, or service-manager configuration is included in this project. For a deployment, adapt the following checklist to your hosting environment:

1. Use a supported Python runtime and install from `requirements.txt` in a clean environment.
2. Provision PostgreSQL on a private network, enable transport encryption where available, and apply `schema.sql` with a database administrator. Use a separate non-owner application login with the grants above.
3. Inject `DB_HOST`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_PORT`, and a randomly generated `SECRET_KEY` through the platform's secret manager. Do not deploy a committed `.env`.
4. Run the application without `--reload` behind a TLS-terminating reverse proxy. Restrict direct access to the application port and allow only the proxy to reach it.
5. Ensure the process working directory is the project root: document storage currently uses the relative `uploads/` directory. Mount it on durable, access-restricted storage, exclude it from public static serving, and back it up separately. Multiple app instances require a shared storage design; local per-instance disks do not provide that.
6. Configure a health check against `/health`, monitor application/database errors, and establish tested backup and restore procedures for both PostgreSQL and uploaded files.
7. Before public exposure, address the limitations in [THREATS.md](THREATS.md), including rate limiting, MFA, content inspection, security headers, and independent audit-log anchoring.

The database, `uploads/`, secret management, TLS, backups, monitoring, and operational processes must be secured by the deployer. This repository does not itself configure a production platform.

## Current limitations

The application has no built-in MFA, login rate limiting, malware scanning, file-content validation, at-rest file encryption, document versioning, or disaster-recovery workflow. The audit hash chain has no independently administered external anchor. These limits and other known risks are described in [THREATS.md](THREATS.md).
