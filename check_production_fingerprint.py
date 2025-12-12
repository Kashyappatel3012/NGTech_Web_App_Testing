"""
Script to check and diagnose fingerprint issues in production
This helps identify what fingerprint is stored vs what should be there
"""
import sys
import io

# Fix encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from app import app, db, User, EmployeeData, validate_browser_fingerprint

def check_all_fingerprints():
    """Check all stored fingerprints in database"""
    with app.app_context():
        print("=" * 70)
        print("Fingerprint Database Check")
        print("=" * 70)
        
        # Get all users with fingerprints
        all_employees = EmployeeData.query.filter(EmployeeData.browser_fingerprint.isnot(None)).all()
        
        if not all_employees:
            print("\n❌ No fingerprints found in database!")
            return
        
        print(f"\n✅ Found {len(all_employees)} user(s) with fingerprints:\n")
        
        for emp in all_employees:
            user = db.session.get(User, emp.user_id)
            if user:
                stored_fp = emp.browser_fingerprint.strip() if emp.browser_fingerprint else ''
                print(f"User: {user.username} ({user.employee_name})")
                print(f"  Department: {user.department}")
                print(f"  Fingerprint: {stored_fp}")
                print(f"  Length: {len(stored_fp)} characters")
                print(f"  Format: {'✅ Valid MD5' if len(stored_fp) == 32 and all(c in '0123456789abcdef' for c in stored_fp.lower()) else '❌ Invalid format'}")
                print()
        
        # Test with reference fingerprint
        reference_fp = "396520d70ea1f79dd21caffd85085795"
        print("=" * 70)
        print(f"Testing with reference fingerprint: {reference_fp}")
        print("=" * 70)
        
        is_valid, user_found = validate_browser_fingerprint(reference_fp, None)
        print(f"\nValidation result: {'✅ VALID' if is_valid else '❌ INVALID'}")
        if user_found:
            print(f"Matched user: {user_found.username} ({user_found.employee_name})")
        else:
            print("No matching user found")
            print("\n💡 This means the reference fingerprint is NOT in the database.")
            print("   You need to update the database with the fingerprint from /generate_fingerprint")

if __name__ == '__main__':
    try:
        check_all_fingerprints()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

