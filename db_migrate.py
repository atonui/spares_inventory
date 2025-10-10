# Run this once to add profile management columns

import sqlite3
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE = os.getenv("DATABASE_URL")

def migrate_database():
    """Add columns needed for profile management"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    try:
        # Add reset token columns to users table
        print("Adding reset token columns...")
        cursor.execute("""
            ALTER TABLE users 
            ADD COLUMN reset_token TEXT NULL
        """)
        
        cursor.execute("""
            ALTER TABLE users 
            ADD COLUMN reset_token_expires TEXT NULL
        """)
        
        print("✅ Database migration completed successfully!")
        
    except sqlite3.OperationalError as e:
        if "duplicate column" in str(e).lower():
            print("⚠️  Columns already exist, skipping migration")
        else:
            print(f"❌ Migration error: {e}")
            raise
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate_database()