import sqlite3
from passlib.context import CryptContext
from dotenv import load_dotenv
import os

load_dotenv()
DATABASE = os.getenv("DATABASE_URL", "inventory.db")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def migrate_passwords():
    """
    Migrate existing SHA256 passwords to bcrypt.
    
    IMPORTANT: This requires users to have their passwords reset
    since we can't decrypt SHA256 hashes.
    """
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    
    print("=" * 60)
    print("PASSWORD MIGRATION TO BCRYPT")
    print("=" * 60)
    
    # Get all users
    cursor.execute("SELECT id, email, name, password_hash FROM users")
    users = cursor.fetchall()
    
    print(f"\nFound {len(users)} users")
    print("\n⚠️  IMPORTANT: Existing password hashes cannot be migrated.")
    print("You have two options:")
    print("1. Reset all user passwords to a temporary password")
    print("2. Have users use 'Forgot Password' to reset individually")
    
    choice = input("\nChoose option (1 or 2): ")
    
    if choice == "1":
        temp_password = input("Enter temporary password for all users (min 8 chars): ")
        if len(temp_password) < 8:
            print("❌ Password too short!")
            return
        
        new_hash = pwd_context.hash(temp_password)
        
        for user_id, email, name, old_hash in users:
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user_id)
            )
            print(f"✅ Updated: {name} ({email})")
        
        conn.commit()
        print(f"\n✅ All {len(users)} users updated with temporary password")
        print(f"⚠️  IMPORTANT: Users must change password on first login!")
        
    elif choice == "2":
        print("\n✅ No changes made.")
        print("Users will need to use 'Forgot Password' to reset.")
        print("\nTo force password reset for a specific user:")
        print("UPDATE users SET password_hash = NULL WHERE email = 'user@example.com';")
    
    else:
        print("❌ Invalid choice. Aborted.")
    
    conn.close()
    print("=" * 60)

if __name__ == "__main__":
    migrate_passwords()