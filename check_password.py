
import os
import psycopg
from getpass import getpass
from dotenv import load_dotenv
from pwdlib import PasswordHash

load_dotenv()

password_hash = PasswordHash.recommended()

email = input("Enter registered email: ").strip()
password = getpass("Enter your registered password: ")

try:
    with psycopg.connect(
        host=os.getenv("DB_HOST"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=os.getenv("DB_PORT")
    ) as conn:

        with conn.cursor() as cur:
            cur.execute(
                "SELECT password_hash FROM users WHERE email = %s",
                (email,)
            )
            result = cur.fetchone()

    if result:
        is_valid = password_hash.verify(password, result[0])

        if is_valid:
            print("Password verification: SUCCESS")
        else:
            print("Password verification: FAILED")
    else:
        print("User not found!")

except Exception as error:
    print("Error:", error)
