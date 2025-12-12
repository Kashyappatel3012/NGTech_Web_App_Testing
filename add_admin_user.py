"""
Script to add Admin user: Kashyap Patel
"""
import sys
import io

# Fix encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from app import app, db, User, EmployeeData, UserStatus
from werkzeug.security import generate_password_hash
from datetime import datetime

def add_admin_user():
    """Add Admin user: Kashyap Patel"""
    with app.app_context():
        print("=" * 70)
        print("Add Admin User: Kashyap Patel")
        print("=" * 70)
        
        # Check if user already exists
        existing_user = User.query.filter_by(email='patelkashyap3012@gmail.com').first()
        if existing_user:
            print(f"\n⚠️  User with email 'patelkashyap3012@gmail.com' already exists!")
            print(f"   Username: {existing_user.username}")
            print(f"   Name: {existing_user.employee_name}")
            response = input("\nDo you want to update this user? (yes/no): ")
            if response.lower() != 'yes':
                print("❌ Operation cancelled.")
                return False
            user = existing_user
        else:
            user = None
        
        # User details
        username = "kashyap.patel"
        employee_name = "Kashyap Patel"
        email = "patelkashyap3012@gmail.com"
        department = "Admin"
        password = "Admin@2024"  # Default password - should be changed on first login
        browser_fingerprint = "24769342a752806361471a8e6db5f78d"
        
        try:
            if user:
                # Update existing user
                print(f"\n📝 Updating existing user...")
                user.username = username
                user.employee_name = employee_name
                user.email = email
                user.department = department
                user.password = generate_password_hash(password)
            else:
                # Create new user
                print(f"\n➕ Creating new user...")
                user = User(
                    username=username,
                    employee_name=employee_name,
                    password=generate_password_hash(password),
                    email=email,
                    department=department,
                    created_at=datetime.now()
                )
                db.session.add(user)
                db.session.flush()  # Get the user ID
            
            # Create or update EmployeeData
            employee_data = EmployeeData.query.filter_by(user_id=user.id).first()
            if not employee_data:
                employee_data = EmployeeData(
                    user_id=user.id,
                    browser_fingerprint=browser_fingerprint,
                    position="Admin",
                    created_at=datetime.now()
                )
                db.session.add(employee_data)
                print("   ✅ Created EmployeeData")
            else:
                employee_data.browser_fingerprint = browser_fingerprint
                employee_data.position = "Admin"
                print("   ✅ Updated EmployeeData")
            
            # Create or update UserStatus
            user_status = UserStatus.query.filter_by(user_id=user.id).first()
            if not user_status:
                user_status = UserStatus(
                    user_id=user.id,
                    is_active=True,
                    failed_attempts=0
                )
                db.session.add(user_status)
                print("   ✅ Created UserStatus")
            else:
                user_status.is_active = True
                print("   ✅ Updated UserStatus")
            
            # Commit all changes
            db.session.commit()
            
            print(f"\n✅ SUCCESS! User created/updated:")
            print(f"   - Username: {username}")
            print(f"   - Name: {employee_name}")
            print(f"   - Email: {email}")
            print(f"   - Department: {department}")
            print(f"   - Password: {password} (default - should be changed)")
            print(f"   - Browser Fingerprint: {browser_fingerprint}")
            print(f"   - User ID: {user.id}")
            print(f"   - Status: Active")
            
            # Verify
            db.session.refresh(user)
            db.session.refresh(employee_data)
            
            if employee_data.browser_fingerprint == browser_fingerprint:
                print(f"\n✅ Verification: Browser fingerprint stored correctly!")
            else:
                print(f"\n⚠️  Warning: Fingerprint mismatch!")
            
            return True
            
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ ERROR: Failed to create/update user: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    try:
        success = add_admin_user()
        
        print("\n" + "=" * 70)
        if success:
            print("✅ Script completed successfully!")
        else:
            print("❌ Script failed!")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n\n❌ Operation cancelled by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

