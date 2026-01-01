import os
import psycopg2
from backend.config import DATABASE_URL

def clear_data():
    if not DATABASE_URL:
        print("Error: DATABASE_URL not found.")
        return

    print("Connecting to database...")
    try:
        conn = psycopg2.connect(DATABASE_URL)
        cur = conn.cursor()
        
        print("Clearing vouchers table...")
        cur.execute("TRUNCATE TABLE vouchers;")
        
        conn.commit()
        cur.close()
        conn.close()
        print("Success: Vouchers table cleared.")
    except Exception as e:
        print(f"Error clearing database: {e}")

if __name__ == "__main__":
    clear_data()
