import sqlite3
import csv
import sys
from main import DATABASE


def get_valid_store_types():
    """Get list of valid active store types"""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT type_code, type_name 
        FROM store_types 
        WHERE is_active = 1
    """)
    types = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    return types


def import_stores_from_csv(csv_file):
    """Import stores from CSV file with store type validation"""
    valid_types = get_valid_store_types()

    if not valid_types:
        print("❌ No active store types found in database!")
        print("Please add store types first using the admin panel.")
        return

    print("\n✅ Valid store types:")
    for code, name in valid_types.items():
        print(f"   - {code}: {name}")
    print()

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    added = 0
    skipped = 0
    errors = []

    with open(csv_file, "r") as f:
        reader = csv.DictReader(f)
        for row_num, row in enumerate(reader, start=2):
            try:
                # Validate store type
                store_type = row["type"].strip().lower()
                if store_type not in valid_types:
                    errors.append(
                        f"Row {row_num}: Invalid store type '{row['type']}'. Valid types: {', '.join(valid_types.keys())}"
                    )
                    skipped += 1
                    continue

                # Find user ID by email if provided
                assigned_user_id = None
                if row.get("assigned_user_email"):
                    cursor.execute(
                        "SELECT id FROM users WHERE email = ?",
                        (row["assigned_user_email"],),
                    )
                    user = cursor.fetchone()
                    if user:
                        assigned_user_id = user[0]
                    else:
                        print(
                            f"⚠️  Warning Row {row_num}: User '{row['assigned_user_email']}' not found, store will be unassigned"
                        )

                cursor.execute(
                    """
                    INSERT INTO stores (name, type, location, assigned_user_id)
                    VALUES (?, ?, ?, ?)
                """,
                    (
                        row["name"],
                        store_type,
                        row.get("location", ""),
                        assigned_user_id,
                    ),
                )
                added += 1
                print(f"✅ Added: {row['name']} ({valid_types[store_type]})")
            except Exception as e:
                errors.append(f"Row {row_num}: {row.get('name', 'unknown')} - {str(e)}")
                skipped += 1
                print(
                    f"❌ Error Row {row_num}: {row.get('name', 'unknown')} - {str(e)}"
                )

    conn.commit()
    conn.close()

    print(f"\n📊 Summary: Added {added}, Skipped {skipped}")

    if errors:
        print("\n❌ Detailed Errors:")
        for error in errors:
            print(f"  - {error}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python import_stores.py stores.csv")
        print("\nCSV format: name,type,location,assigned_user_email")
        print("\nStore type must match a type_code from store_types table")
        sys.exit(1)

    import_stores_from_csv(sys.argv[1])
