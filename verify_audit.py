from dotenv import load_dotenv

import main


load_dotenv()


def verify_audit_chain():
    with main.get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    id,
                    rtrim(prev_hash),
                    rtrim(entry_hash),
                    encode(
                        public.digest(
                            convert_to(
                                jsonb_build_object(
                                    'id', id,
                                    'user_id', user_id,
                                    'document_id', document_id,
                                    'action', action,
                                    'details', details,
                                    'success', success,
                                    'created_at', created_at,
                                    'prev_hash', rtrim(prev_hash)
                                )::text,
                                'UTF8'
                            ),
                            'sha256'
                        ),
                        'hex'
                    )
                FROM public.audit_logs
                ORDER BY id
                """
            )
            entries = cur.fetchall()
            cur.execute(
                "SELECT rtrim(head_hash) FROM public.audit_chain_state WHERE singleton = TRUE"
            )
            state = cur.fetchone()

    previous_hash = "0" * 64
    for entry_id, stored_previous, stored_hash, calculated_hash in entries:
        if stored_previous != previous_hash or stored_hash != calculated_hash:
            print(f"Audit chain verification failed at event {entry_id}.")
            return False
        previous_hash = stored_hash

    expected_head = state[0] if state else "0" * 64
    if expected_head != previous_hash:
        print("Audit chain head does not match the final event.")
        return False

    print(f"Audit chain verified: {len(entries)} events.")
    return True


if __name__ == "__main__":
    raise SystemExit(0 if verify_audit_chain() else 1)