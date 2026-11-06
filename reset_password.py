
import os
import psycopg
from getpass import getpass
from dotenv import load_dotenv
from pwdlib import PasswordHash

load_dotenv()

password_hash = PasswordHash.recommended()

email = input("Enter registered email: ").strip()
current_password = getpass("Enter current password: ")
new_password = getpass("Enter new password: ")

if len(new_password) < 8:
    print("Password must contain at least 8 characters.")
else:
    with psycopg.connect(
        host=os.getenv("DB_HOST"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=os.getenv("DB_PORT")
    ) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, password_hash
                FROM users
                WHERE email = %s AND is_active = TRUE
                FOR UPDATE
                """,
                (email,)
            )
            result = cur.fetchone()

            if not result:
                print("Active user not found.")
            elif not password_hash.verify(current_password, result[1]):
                print("Current password is incorrect.")
            else:
                cur.execute(
                    """
                    UPDATE users
                    SET password_hash = %s
                    WHERE id = %s
                    """,
                    (password_hash.hash(new_password), result[0])
                )
                print("Password changed successfully.")
