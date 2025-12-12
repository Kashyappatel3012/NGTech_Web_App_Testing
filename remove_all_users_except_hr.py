"""
Script to remove all users from database except HR Manager
WARNING: This will permanently delete all users and their data except HR Manager!
"""
import sys
import io

# Fix encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

from app import app, db, User, EmployeeData, UserStatus, LoginActivity, Performance

def remove_all_users_except_hr():
    """Remove all users except HR Manager"""
    with app.app_context():
        print("=" * 70)
        print("Remove All Users Except HR Manager")
        print("=" * 70)
        print("\n⚠️  WARNING: This will permanently delete all users except HR Manager!")
        print("   This includes all their:")
        print("   - Employee Data")
        print("   - Login Activities")
        print("   - User Status")
        print("   - Performance Records")
        print("   - All other related data")
        print("\n" + "=" * 70)
        
        # Find HR Manager
        hr_manager = User.query.filter_by(username='hr_user').first()
        if not hr_manager:
            hr_manager = User.query.filter_by(department='HR').first()
        
        if not hr_manager:
            print("\n❌ ERROR: HR Manager user not found!")
            print("   Cannot proceed without HR Manager user.")
            return False
        
        print(f"\n✅ Found HR Manager:")
        print(f"   - Username: {hr_manager.username}")
        print(f"   - Name: {hr_manager.employee_name}")
        print(f"   - Department: {hr_manager.department}")
        print(f"   - User ID: {hr_manager.id}")
        print(f"   - Email: {hr_manager.email}")
        
        # Get all users except HR Manager
        all_users = User.query.filter(User.id != hr_manager.id).all()
        
        if not all_users:
            print("\n✅ No other users found. Database already clean!")
            return True
        
        print(f"\n📋 Found {len(all_users)} user(s) to delete:")
        for user in all_users:
            print(f"   - {user.username} ({user.employee_name}) - {user.department}")
        
        # Count related records
        total_activities = LoginActivity.query.filter(LoginActivity.user_id != hr_manager.id).count()
        total_performance = Performance.query.filter(Performance.user_id != hr_manager.id).count()
        
        print(f"\n📊 Related records to be deleted:")
        print(f"   - Login Activities: {total_activities}")
        print(f"   - Performance Records: {total_performance}")
        print(f"   - Employee Data: {len(all_users)} (one per user)")
        print(f"   - User Status: {len(all_users)} (one per user)")
        
        # Confirm (skip if running non-interactively)
        print("\n" + "=" * 70)
        if len(sys.argv) > 1 and sys.argv[1] == '--auto':
            print("⚠️  Auto-delete mode enabled (--auto flag)")
            response = 'DELETE'
        else:
            try:
                response = input("Type 'DELETE' to confirm deletion: ")
            except (EOFError, KeyboardInterrupt):
                print("\n❌ Deletion cancelled (non-interactive mode).")
                print("   To run automatically, use: python remove_all_users_except_hr.py --auto")
                return False
        
        if response != 'DELETE':
            print("\n❌ Deletion cancelled.")
            return False
        
        print("\n🗑️  Starting deletion...")
        
        try:
            # Delete users (cascade will handle related records)
            deleted_count = 0
            for user in all_users:
                try:
                    # Delete user (cascade will delete related records)
                    db.session.delete(user)
                    deleted_count += 1
                    print(f"   ✅ Deleted: {user.username}")
                except Exception as e:
                    print(f"   ❌ Error deleting {user.username}: {e}")
                    db.session.rollback()
                    continue
            
            # Commit all deletions
            db.session.commit()
            
            print(f"\n✅ Successfully deleted {deleted_count} user(s)!")
            
            # Verify
            remaining_users = User.query.all()
            print(f"\n📊 Remaining users: {len(remaining_users)}")
            for user in remaining_users:
                print(f"   - {user.username} ({user.employee_name}) - {user.department}")
            
            if len(remaining_users) == 1 and remaining_users[0].id == hr_manager.id:
                print("\n✅ SUCCESS! Only HR Manager remains in database.")
                return True
            else:
                print("\n⚠️  WARNING: Unexpected users found after deletion!")
                return False
                
        except Exception as e:
            db.session.rollback()
            print(f"\n❌ ERROR: Failed to delete users: {e}")
            import traceback
            traceback.print_exc()
            return False

if __name__ == '__main__':
    try:
        success = remove_all_users_except_hr()
        
        print("\n" + "=" * 70)
        if success:
            print("✅ Script completed successfully!")
        else:
            print("❌ Script completed with errors!")
        print("=" * 70)
        
    except KeyboardInterrupt:
        print("\n\n❌ Operation cancelled by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

