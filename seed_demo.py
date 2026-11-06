import os
from pathlib import Path

from dotenv import load_dotenv

import main


load_dotenv()

ACCOUNTS = (
    ("admin", "DEMO Administrator", "admin.test@example.com", "SEED_ADMIN_PASSWORD"),
    ("owner", "Demo Owner", "owner.test@example.com", "SEED_OWNER_PASSWORD"),
    ("viewer", "Demo Viewer", "viewer.test@example.com", "SEED_VIEWER_PASSWORD"),
)
SAMPLE_NAME = "Quarterly-services-agreement.txt"
SAMPLE_CATEGORY = "Contracts"
SAMPLE_CONTENT = "Demo document. Grant only the access needed for each recipient.\n"


def seed_demo():
    missing = [env_name for _, _, _, env_name in ACCOUNTS if not os.getenv(env_name)]
    if missing:
        raise RuntimeError(f"Set these environment variables first: {', '.join(missing)}")

    account_ids = {}
    account_emails = {}
    with main.get_connection() as conn:
        with conn.cursor() as cur:
            for role, full_name, default_email, password_env in ACCOUNTS:
                email = os.getenv(f"SEED_{role.upper()}_EMAIL", default_email)
                cur.execute(
                    """
                    INSERT INTO users (full_name, email, password_hash, role, is_active)
                    VALUES (%s, %s, %s, %s, TRUE)
                    ON CONFLICT (email) DO NOTHING
                    RETURNING id
                    """,
                    (full_name, email, main.hash_password(os.environ[password_env]), role)
                )
                account = cur.fetchone()
                if not account:
                    raise RuntimeError(
                        f"Refusing to modify existing account for {email}; "
                        "use a dedicated demo email."
                    )
                account_ids[role] = account[0]
                account_emails[role] = email

            owner_id = account_ids["owner"]
            viewer_id = account_ids["viewer"]
            cur.execute(
                "SELECT id, storage_path FROM documents WHERE owner_id = %s AND name = %s",
                (owner_id, SAMPLE_NAME)
            )
            document = cur.fetchone()

            if document:
                document_id, stored_path = document
                sample_path = Path(stored_path)
            else:
                main.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                sample_path = main.UPLOAD_DIR / "seeded-agreement.txt"
                if not sample_path.exists():
                    sample_path.write_text(SAMPLE_CONTENT, encoding="utf-8")
                cur.execute(
                    """
                    INSERT INTO documents (name, category, owner_id, storage_path)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                    """,
                    (SAMPLE_NAME, SAMPLE_CATEGORY, owner_id, str(sample_path))
                )
                document_id = cur.fetchone()[0]

            cur.execute(
                """
                INSERT INTO permissions (document_id, user_id, access_type, granted_by)
                VALUES (%s, %s, 'READ', %s)
                ON CONFLICT (document_id, user_id) DO NOTHING
                """,
                (document_id, viewer_id, owner_id)
            )

            cur.execute(
                """
                SELECT id FROM audit_logs
                WHERE action = 'SEED' AND document_id = %s
                LIMIT 1
                """,
                (document_id,)
            )
            if not cur.fetchone():
                cur.execute(
                    """
                    INSERT INTO audit_logs
                    (user_id, document_id, action, details, success)
                    VALUES (%s, %s, 'SEED', 'Demo document initialized', TRUE)
                    """,
                    (owner_id, document_id)
                )

    print("Demo accounts and one shared sample document are ready.")
    print(f"Emails: {', '.join(account_emails.values())}")
    print("Passwords were read from SEED_*_PASSWORD and were not printed.")


if __name__ == "__main__":
    seed_demo()