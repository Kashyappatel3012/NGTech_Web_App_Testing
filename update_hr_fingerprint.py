"""
Simple script to update HR Manager browser fingerprint in database
Stores fingerprint as plain text (unencrypted) for compatibility
"""
import sys
import io

# Fix encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from app import app, db, User, EmployeeData

def update_hr_manager_fingerprint(new_fingerprint):
    """
    Update HR Manager's browser fingerprint in database
    
    Args:
        new_fingerprint: The new browser fingerprint to set (e.g., '6fc7c55b2ee9afd4dd8e9454b3a93ca6')
    """
    with app.app_context():
        # Find HR Manager user - try different methods
        hr_manager = None
        
        # Try finding by username 'hr_user'
        hr_manager = User.query.filter_by(username='hr_user').first()
        
        # If not found, try by department
        if not hr_manager:
            hr_manager = User.query.filter_by(department='HR').first()
        
        # If still not found, list all users
        if not hr_manager:
            all_users = User.query.all()
            print(f"❌ HR Manager user not found!")
            print(f"Available users:")
            for user in all_users:
                print(f"  - Username: {user.username}, Department: {user.department}, Name: {user.employee_name}")
            return False
        
        print(f"✅ Found HR Manager user:")
        print(f"   - Username: {hr_manager.username}")
        print(f"   - Name: {hr_manager.employee_name}")
        print(f"   - Department: {hr_manager.department}")
        print(f"   - User ID: {hr_manager.id}")
        
        # Get employee data
        employee_data = EmployeeData.query.filter_by(user_id=hr_manager.id).first()
        if not employee_data:
            print("❌ Employee data not found for HR Manager!")
            print("   Creating EmployeeData record...")
            employee_data = EmployeeData(user_id=hr_manager.id)
            db.session.add(employee_data)
        
        # Show current fingerprint if it exists
        if employee_data.browser_fingerprint:
            print(f"\n📋 Current Fingerprint: {employee_data.browser_fingerprint}")
            print(f"   Length: {len(employee_data.browser_fingerprint)} characters")
        else:
            print("\n📋 No current fingerprint stored in database")
        
        # Validate new fingerprint format
        new_fingerprint = new_fingerprint.strip()
        if not new_fingerprint:
            print("❌ Error: New fingerprint cannot be empty!")
            return False
        
        print(f"\n📝 New Fingerprint: {new_fingerprint}")
        print(f"   Length: {len(new_fingerprint)} characters")
        
        # Check if it's MD5 (32 chars) or SHA-256 (64 chars)
        if len(new_fingerprint) == 32:
            print("   Type: MD5 (32 characters) ✅")
        elif len(new_fingerprint) == 64:
            print("   Type: SHA-256 (64 characters) ✅")
        else:
            print(f"   Type: Unknown format ({len(new_fingerprint)} characters)")
            print("   ⚠️  Warning: Expected MD5 (32 chars) or SHA-256 (64 chars)")
        
        # Update the fingerprint - store as plain text (unencrypted) for compatibility
        try:
            employee_data.browser_fingerprint = new_fingerprint
            print(f"   - Storing as: Plain text (unencrypted)")
            
            # Commit to database
            db.session.commit()
            
            print(f"\n✅ SUCCESS! Fingerprint updated in database")
            print(f"   - User: {hr_manager.username} ({hr_manager.employee_name})")
            print(f"   - New Fingerprint: {new_fingerprint}")
            
            # Verify the update
            db.session.refresh(employee_data)
            if employee_data.browser_fingerprint == new_fingerprint:
                print(f"\n✅ Verification: Fingerprint matches!")
                print(f"   Stored value: {employee_data.browser_fingerprint}")
            else:
                print(f"\n⚠️  Warning: Verification failed - fingerprint doesn't match!")
                print(f"   Expected: {new_fingerprint}")
                print(f"   Got: {employee_data.browser_fingerprint}")
            
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ ERROR: Failed to update fingerprint: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    # Set the fingerprint to the specified value
    new_fingerprint = "396520d70ea1f79dd21caffd85085795"
    print("=" * 60)
    print("HR Manager Browser Fingerprint Update Script")
    print("=" * 60)
    print(f"\nTarget Fingerprint: {new_fingerprint}\n")
    
    success = update_hr_manager_fingerprint(new_fingerprint)
    
    print("\n" + "=" * 60)
    if success:
        print("✅ Script completed successfully!")
        print("=" * 60)
    else:
        print("❌ Script failed!")
        print("=" * 60)

