# Remove All Users Except HR Manager - Instructions

## ✅ Local Database - COMPLETED

All users except HR Manager have been successfully removed from your local database.

**Remaining user:**
- Username: `hr_user`
- Name: HR Manager
- Department: HR
- Email: pubglover3012@gmail.com

## 📋 For Production Database (Render.com)

To remove all users except HR Manager from your production PostgreSQL database:

### Option 1: Using Python Script (Recommended)

1. **Connect to production database** (if you have SSH access):
   ```bash
   # Set production database URL
   export DATABASE_URL="your_production_postgresql_url"
   python remove_all_users_except_hr.py --auto
   ```

### Option 2: Using SQL Script (Direct)

1. **Go to Render.com Dashboard**
2. **Select your PostgreSQL database**
3. **Open the "Connect" or "Console" tab**
4. **Run the SQL script** (`remove_all_users_except_hr.sql`):

```sql
BEGIN;

-- Delete Login Activities for non-HR users
DELETE FROM login_activity 
WHERE user_id NOT IN (
    SELECT id FROM "user" 
    WHERE username = 'hr_user' OR department = 'HR'
    LIMIT 1
);

-- Delete Performance Records for non-HR users
DELETE FROM performance 
WHERE user_id NOT IN (
    SELECT id FROM "user" 
    WHERE username = 'hr_user' OR department = 'HR'
    LIMIT 1
);

-- Delete User Status for non-HR users
DELETE FROM user_status 
WHERE user_id NOT IN (
    SELECT id FROM "user" 
    WHERE username = 'hr_user' OR department = 'HR'
    LIMIT 1
);

-- Delete Employee Data for non-HR users
DELETE FROM employee_data 
WHERE user_id NOT IN (
    SELECT id FROM "user" 
    WHERE username = 'hr_user' OR department = 'HR'
    LIMIT 1
);

-- Finally, delete all users except HR Manager
DELETE FROM "user" 
WHERE id NOT IN (
    SELECT id FROM "user" 
    WHERE username = 'hr_user' OR department = 'HR'
    LIMIT 1
);

-- Verify only HR Manager remains
SELECT 
    id,
    username,
    employee_name,
    department,
    email
FROM "user";

COMMIT;
```

### Option 3: Manual SQL (Step by Step)

If you prefer to run commands one by one:

```sql
-- 1. Check current users
SELECT id, username, employee_name, department FROM "user";

-- 2. Find HR Manager ID
SELECT id FROM "user" WHERE username = 'hr_user' OR department = 'HR' LIMIT 1;

-- 3. Delete related records (replace <hr_user_id> with actual ID)
DELETE FROM login_activity WHERE user_id != <hr_user_id>;
DELETE FROM performance WHERE user_id != <hr_user_id>;
DELETE FROM user_status WHERE user_id != <hr_user_id>;
DELETE FROM employee_data WHERE user_id != <hr_user_id>;

-- 4. Delete users
DELETE FROM "user" WHERE id != <hr_user_id>;

-- 5. Verify
SELECT id, username, employee_name, department FROM "user";
```

## ⚠️ Important Notes

1. **This is PERMANENT** - Deleted data cannot be recovered
2. **Backup first** - Consider backing up your database before deletion
3. **Cascade deletes** - Related records (EmployeeData, LoginActivity, UserStatus, Performance) will be automatically deleted due to cascade relationships
4. **HR Manager preserved** - Only the user with username `hr_user` or department `HR` will remain

## ✅ Verification

After deletion, verify:
- Only 1 user remains (HR Manager)
- All related records for deleted users are gone
- HR Manager can still login

## Files Created

- `remove_all_users_except_hr.py` - Python script (supports `--auto` flag)
- `remove_all_users_except_hr.sql` - SQL script for direct execution

