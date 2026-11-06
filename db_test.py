import os
import psycopg
from dotenv import load_dotenv

load_dotenv()

try:
    conn = psycopg.connect(
        host=os.getenv("DB_HOST"),
        dbname=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        port=os.getenv("DB_PORT")
    )

    print("Database connected successfully!")

    conn.close()

except Exception:
    print("Database connection failed. Check the DB_* settings in .env.")