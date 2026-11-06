import os
from pathlib import Path
from uuid import uuid4

import main


SAMPLES = (
    (
        "Quarterly-budget.txt",
        "Finance",
        "Demo budget summary for testing document search and downloads.\n",
        "READ",
    ),
    (
        "Vendor-contract.txt",
        "Contracts",
        "Demo vendor agreement for testing document editing and grants.\n",
        "EDIT",
    ),
    (
        "Internal-roadmap.txt",
        "Planning",
        "Private owner-only demo document; viewers should not see this file.\n",
        None,
    ),
)


def seed_sample_documents():
    owner_email = os.getenv("SEED_OWNER_EMAIL")
    viewer_email = os.getenv("SEED_VIEWER_EMAIL")
    if not owner_email or not viewer_email:
        raise RuntimeError("Set SEED_OWNER_EMAIL and SEED_VIEWER_EMAIL to dedicated demo accounts.")

    created_paths = []
    try:
        with main.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT id FROM users
                    WHERE email = %s AND role = 'owner' AND is_active = TRUE
                    """,
                    (owner_email,)
                )
                owner = cur.fetchone()
                if not owner:
                    raise RuntimeError("Configured active demo owner account was not found.")
                owner_id = owner[0]

                cur.execute(
                    """
                    SELECT id FROM users
                    WHERE email = %s AND role = 'viewer' AND is_active = TRUE
                    """,
                    (viewer_email,)
                )
                viewer = cur.fetchone()
                if not viewer:
                    raise RuntimeError("Configured active demo viewer account was not found.")
                viewer_id = viewer[0]
                main.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
                created_count = 0

                for name, category, contents, access_type in SAMPLES:
                    cur.execute(
                        "SELECT id FROM documents WHERE owner_id = %s AND name = %s",
                        (owner_id, name)
                    )
                    existing = cur.fetchone()
                    if existing:
                        document_id = existing[0]
                    else:
                        stored_path = main.UPLOAD_DIR / f"{uuid4().hex}.txt"
                        with stored_path.open("x", encoding="utf-8") as sample_file:
                            created_paths.append(stored_path)
                            sample_file.write(contents)
                        cur.execute(
                            """
                            INSERT INTO documents (name, category, owner_id, storage_path)
                            VALUES (%s, %s, %s, %s)
                            RETURNING id
                            """,
                            (name, category, owner_id, str(stored_path))
                        )
                        document_id = cur.fetchone()[0]
                        cur.execute(
                            """
                            INSERT INTO audit_logs
                            (user_id, document_id, action, details, success)
                            VALUES (%s, %s, 'UPLOAD', %s, TRUE)
                            """,
                            (owner_id, document_id, f"Seeded demo document: {name}")
                        )
                        created_count += 1

                    if viewer_id and access_type:
                        cur.execute(
                            """
                            INSERT INTO permissions
                            (document_id, user_id, access_type, granted_by)
                            VALUES (%s, %s, %s, %s)
                            ON CONFLICT (document_id, user_id) DO NOTHING
                            """,
                            (document_id, viewer_id, access_type, owner_id)
                        )
                        if cur.rowcount:
                            cur.execute(
                                """
                                INSERT INTO audit_logs
                                (user_id, document_id, action, details, success)
                                VALUES (%s, %s, 'PERMISSION_GRANTED', %s, TRUE)
                                """,
                                (
                                    owner_id,
                                    document_id,
                                    f"Seeded {access_type} demo grant for viewer account {viewer_id}"
                                )
                            )

        print(f"Created {created_count} sample documents; existing samples were left intact.")
        print("The configured demo viewer receives READ and EDIT grants only when no grant already exists.")
        print("The private sample stays owner-only.")
    except Exception:
        for path in created_paths:
            path.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    seed_sample_documents()
