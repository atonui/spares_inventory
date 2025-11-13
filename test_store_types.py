import sqlite3
from main import DATABASE


def test_store_types():
    """Test store types functionality"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("=" * 60)
    print("STORE TYPES TESTING")
    print("=" * 60)

    # Test 1: Check if store_types table exists
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='store_types'"
    )
    if cursor.fetchone():
        print("\n✅ store_types table exists")
    else:
        print("\n❌ store_types table not found!")
        return

    # Test 2: Count store types
    cursor.execute("SELECT COUNT(*) FROM store_types")
    count = cursor.fetchone()[0]
    print(f"✅ Found {count} store types")

    # Test 3: List all store types
    cursor.execute("""
        SELECT type_code, type_name, is_active, display_order 
        FROM store_types 
        ORDER BY display_order, type_name
    """)
    types = cursor.fetchall()

    print("\n📋 Store Types:")
    for type_code, type_name, is_active, display_order in types:
        status = "✅ Active" if is_active else "❌ Inactive"
        print(f"   [{display_order}] {type_name} ({type_code}) - {status}")

    # Test 4: Check stores using each type
    print("\n📊 Store Type Usage:")
    for type_code, type_name, is_active, display_order in types:
        cursor.execute("SELECT COUNT(*) FROM stores WHERE type = ?", (type_code,))
        store_count = cursor.fetchone()[0]
        print(f"   {type_name}: {store_count} stores")

    # Test 5: Check for stores with invalid types
    cursor.execute("""
        SELECT DISTINCT s.type 
        FROM stores s 
        LEFT JOIN store_types st ON s.type = st.type_code 
        WHERE st.id IS NULL
    """)
    invalid_types = cursor.fetchall()

    if invalid_types:
        print("\n⚠️  WARNING: Stores with invalid/missing store types:")
        for (invalid_type,) in invalid_types:
            cursor.execute(
                "SELECT COUNT(*) FROM stores WHERE type = ?", (invalid_type,)
            )
            count = cursor.fetchone()[0]
            print(f"   - '{invalid_type}': {count} stores")
    else:
        print("\n✅ All stores have valid store types")

    conn.close()

    print("\n" + "=" * 60)
    print("✅ Testing Complete!")
    print("=" * 60)


if __name__ == "__main__":
    test_store_types()
