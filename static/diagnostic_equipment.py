# diagnostic_equipment.py - Run this to check your equipment setup

import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE = os.getenv("DATABASE_URL", "inventory.db")

def check_database():
    """Check if database tables exist"""
    print("=" * 60)
    print("DATABASE CHECKS")
    print("=" * 60)
    
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        
        print(f"\n✓ Connected to database: {DATABASE}")
        print(f"\n📋 Tables found ({len(tables)}):")
        for table in sorted(tables):
            print(f"   - {table}")
        
        # Check equipment table
        if 'equipment' in tables:
            print("\n✓ Equipment table exists")
            cursor.execute("SELECT COUNT(*) FROM equipment")
            count = cursor.fetchone()[0]
            print(f"   Equipment count: {count}")
            
            cursor.execute("PRAGMA table_info(equipment)")
            columns = [row[1] for row in cursor.fetchall()]
            print(f"   Columns: {', '.join(columns)}")
        else:
            print("\n✗ Equipment table MISSING - Run db_migrate_equipment.py")
        
        # Check equipment_history table
        if 'equipment_history' in tables:
            print("\n✓ Equipment history table exists")
            cursor.execute("SELECT COUNT(*) FROM equipment_history")
            count = cursor.fetchone()[0]
            print(f"   History records: {count}")
        else:
            print("\n✗ Equipment history table MISSING - Run db_migrate_equipment.py")
        
        # Check system_settings table
        if 'system_settings' in tables:
            print("\n✓ System settings table exists")
            cursor.execute("SELECT * FROM system_settings WHERE setting_key = 'calibration_reminder_days'")
            setting = cursor.fetchone()
            if setting:
                print(f"   Calibration reminder days: {setting[2]} (setting_value)")
            else:
                print("   ⚠️  Calibration reminder setting missing")
        else:
            print("\n✗ System settings table MISSING - Run db_migrate_equipment.py")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"\n✗ Database error: {e}")
        return False

def check_files():
    """Check if necessary files exist"""
    print("\n" + "=" * 60)
    print("FILE CHECKS")
    print("=" * 60)
    
    files_to_check = [
        ('main.py', 'Main application file'),
        ('static/script.js', 'Frontend JavaScript'),
        ('static/index.html', 'Frontend HTML'),
        ('static/mystyle.css', 'CSS styles'),
        ('calibration_checker.py', 'Calibration checker script'),
        ('.env', 'Environment variables')
    ]
    
    for file_path, description in files_to_check:
        if os.path.exists(file_path):
            size = os.path.getsize(file_path)
            print(f"✓ {description}: {file_path} ({size:,} bytes)")
        else:
            print(f"✗ {description}: {file_path} - NOT FOUND")

def check_main_py():
    """Check if main.py has equipment endpoints"""
    print("\n" + "=" * 60)
    print("MAIN.PY CHECKS")
    print("=" * 60)
    
    if not os.path.exists('main.py'):
        print("✗ main.py not found")
        return False
    
    with open('main.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = [
        ('EquipmentResponse', 'Equipment response model'),
        ('CreateEquipmentRequest', 'Create equipment model'),
        ('@app.get("/api/equipment/stats")', 'Equipment stats endpoint'),
        ('@app.get("/api/equipment")', 'Get equipment endpoint'),
        ('@app.post("/api/equipment")', 'Create equipment endpoint'),
        ('@app.put("/api/equipment/{equipment_id}")', 'Update equipment endpoint'),
        ('@app.post("/api/equipment/{equipment_id}/calibrate")', 'Calibrate endpoint'),
        ('@app.post("/api/equipment/{equipment_id}/transfer")', 'Transfer endpoint'),
        ('@app.get("/api/settings/calibration-reminder-days")', 'Settings endpoint'),
    ]
    
    found = 0
    missing = []
    
    for search_str, description in checks:
        if search_str in content:
            print(f"✓ {description}")
            found += 1
        else:
            print(f"✗ {description} - MISSING")
            missing.append(description)
    
    print(f"\n📊 Found {found}/{len(checks)} equipment endpoints")
    
    if missing:
        print("\n⚠️  Missing endpoints:")
        for item in missing:
            print(f"   - {item}")
    
    return len(missing) == 0

def check_script_js():
    """Check if script.js has equipment functions"""
    print("\n" + "=" * 60)
    print("SCRIPT.JS CHECKS")
    print("=" * 60)
    
    if not os.path.exists('static/script.js'):
        print("✗ static/script.js not found")
        return False
    
    with open('static/script.js', 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = [
        ('equipment: []', 'Equipment state array'),
        ('equipmentStats: {}', 'Equipment stats object'),
        ('showEquipmentPanel:', 'Equipment panel flag'),
        ('async loadEquipment()', 'Load equipment function'),
        ('async loadEquipmentStats()', 'Load stats function'),
        ('async createEquipment()', 'Create equipment function'),
        ('async updateEquipment()', 'Update equipment function'),
        ('async updateCalibration()', 'Update calibration function'),
        ('getCalibrationStatus(', 'Get calibration status function'),
    ]
    
    found = 0
    missing = []
    
    for search_str, description in checks:
        if search_str in content:
            print(f"✓ {description}")
            found += 1
        else:
            print(f"✗ {description} - MISSING")
            missing.append(description)
    
    # Check if loadAllData includes equipment
    if 'loadEquipment()' in content and 'loadAllData()' in content:
        # Find loadAllData function
        start = content.find('async loadAllData()')
        if start > 0:
            end = content.find('}', start + 500)  # Look within 500 chars
            func_content = content[start:end]
            if 'loadEquipment()' in func_content:
                print("✓ loadAllData calls loadEquipment")
                found += 1
            else:
                print("✗ loadAllData doesn't call loadEquipment - MISSING")
                missing.append("loadAllData equipment integration")
    else:
        print("✗ loadAllData equipment integration - MISSING")
        missing.append("loadAllData equipment integration")
    
    # Check closeAllPanels
    if 'closeAllPanels()' in content:
        start = content.find('closeAllPanels()')
        if start > 0:
            end = content.find('}', start + 500)
            func_content = content[start:end]
            if 'showEquipmentPanel' in func_content:
                print("✓ closeAllPanels includes equipment panel")
                found += 1
            else:
                print("✗ closeAllPanels missing equipment panel - MISSING")
                missing.append("closeAllPanels equipment panel")
    
    print(f"\n📊 Found {found}/{len(checks) + 2} equipment components")
    
    if missing:
        print("\n⚠️  Missing components:")
        for item in missing:
            print(f"   - {item}")
    
    return len(missing) == 0

def check_index_html():
    """Check if index.html has equipment UI"""
    print("\n" + "=" * 60)
    print("INDEX.HTML CHECKS")
    print("=" * 60)
    
    if not os.path.exists('static/index.html'):
        print("✗ static/index.html not found")
        return False
    
    with open('static/index.html', 'r', encoding='utf-8') as f:
        content = f.read()
    
    checks = [
        ('equipmentStats.my_equipment', 'My Equipment stat card'),
        ('@click="openPanel(\'showEquipmentPanel\')"', 'Equipment panel click handler'),
        ('x-show="!loading && showEquipmentPanel"', 'Equipment panel display'),
        ('showEquipmentModal', 'Equipment modal flag'),
        ('showCalibrationModal', 'Calibration modal flag'),
        ('showTransferEquipmentModal', 'Transfer modal flag'),
        ('getCalibrationStatus(eq)', 'Calibration status display'),
    ]
    
    found = 0
    missing = []
    
    for search_str, description in checks:
        if search_str in content:
            print(f"✓ {description}")
            found += 1
        else:
            print(f"✗ {description} - MISSING")
            missing.append(description)
    
    print(f"\n📊 Found {found}/{len(checks)} equipment UI components")
    
    if missing:
        print("\n⚠️  Missing UI components:")
        for item in missing:
            print(f"   - {item}")
    
    return len(missing) == 0

def main():
    """Run all diagnostics"""
    print("\n" + "🔍" * 30)
    print("EQUIPMENT SYSTEM DIAGNOSTIC")
    print("🔍" * 30 + "\n")
    
    results = {
        'Database': check_database(),
        'Files': check_files() is not False,  # File check doesn't return boolean
        'Backend (main.py)': check_main_py(),
        'Frontend JS': check_script_js(),
        'Frontend HTML': check_index_html()
    }
    
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    
    all_passed = True
    for check_name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"{status}: {check_name}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 60)
    
    if all_passed:
        print("✅ All checks passed! Equipment system should work.")
        print("\nNext steps:")
        print("1. Restart your server: python main.py")
        print("2. Clear browser cache (Ctrl+Shift+R)")
        print("3. Check browser console for JavaScript errors")
        print("4. Test equipment functionality")
    else:
        print("⚠️  Some checks failed. Please fix the issues above.")
        print("\nCommon fixes:")
        print("1. Run: python db_migrate_equipment.py")
        print("2. Verify all code was copied correctly")
        print("3. Check for syntax errors (missing commas, brackets)")
        print("4. Restart your server")
    
    print("=" * 60 + "\n")

if __name__ == "__main__":
    main()