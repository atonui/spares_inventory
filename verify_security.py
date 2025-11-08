import sqlite3
from main import DATABASE

def verify_security_implementation():
    """Verify all security features are implemented"""
    print("=" * 60)
    print("SECURITY IMPLEMENTATION VERIFICATION")
    print("=" * 60 + "\n")
    
    checks = []
    
    # Check 1: Bcrypt password hashes
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash FROM users LIMIT 1")
    user = cursor.fetchone()
    
    if user and user[0].startswith('$2b$'):
        print("✅ Bcrypt password hashing implemented")
        checks.append(True)
    else:
        print("❌ Bcrypt password hashing NOT implemented")
        checks.append(False)
    
    conn.close()
    
    # Check 2: Rate limiting
    try:
        from main import limiter
        print("✅ Rate limiting configured")
        checks.append(True)
    except:
        print("❌ Rate limiting NOT configured")
        checks.append(False)
    
    # Check 3: HTTPOnly cookies
    try:
        from main import login
        import inspect
        source = inspect.getsource(login)
        if 'httponly=True' in source:
            print("✅ HTTPOnly cookies implemented")
            checks.append(True)
        else:
            print("❌ HTTPOnly cookies NOT implemented")
            checks.append(False)
    except:
        print("⚠️  Could not verify HTTPOnly cookies")
        checks.append(False)
    
    # Check 4: CSRF protection
    try:
        from main import verify_csrf_token
        print("✅ CSRF protection implemented")
        checks.append(True)
    except:
        print("❌ CSRF protection NOT implemented")
        checks.append(False)
    
    print("\n" + "=" * 60)
    if all(checks):
        print("✅ All security features implemented!")
    else:
        print(f"⚠️  {checks.count(False)} security features missing")
    print("=" * 60)

if __name__ == "__main__":
    verify_security_implementation()