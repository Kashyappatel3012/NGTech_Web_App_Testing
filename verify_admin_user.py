"""
Verify Admin user: Kashyap Patel
"""
import sys
import io

# Fix encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from app import app, db, User, EmployeeData, UserStatus

with app.app_context():
    user = User.query.filter_by(username='kashyap.patel').first()
    
    if user:
        print("=" * 70)
        print("Admin User Verification: Kashyap Patel")
        print("=" * 70)
        print(f"\nUser Details:")
        print(f"  - Username: {user.username}")
        print(f"  - Name: {user.employee_name}")
        print(f"  - Email: {user.email}")
        print(f"  - Department: {user.department}")
        print(f"  - User ID: {user.id}")
        print(f"  - Created: {user.created_at}")
        
        emp_data = EmployeeData.query.filter_by(user_id=user.id).first()
        if emp_data:
            print(f"\nEmployee Data:")
            print(f"  - Position: {emp_data.position}")
            print(f"  - Browser Fingerprint: {emp_data.browser_fingerprint}")
            print(f"  - Fingerprint Length: {len(emp_data.browser_fingerprint) if emp_data.browser_fingerprint else 0}")
        
        user_status = UserStatus.query.filter_by(user_id=user.id).first()
        if user_status:
            print(f"\nUser Status:")
            print(f"  - Active: {user_status.is_active}")
            print(f"  - Failed Attempts: {user_status.failed_attempts}")
        
        print("\n" + "=" * 70)
        print("✅ User verified successfully!")
        print("=" * 70)
    else:
        print("❌ User not found!")

