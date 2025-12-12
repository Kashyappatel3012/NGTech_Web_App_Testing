-- SQL script to remove all users except HR Manager
-- WARNING: This will permanently delete all users and their related data!
-- Run this in your database console (SQLite or PostgreSQL)

-- For SQLite (development):
-- sqlite3 instance/db.sqlite < remove_all_users_except_hr.sql

-- For PostgreSQL (production):
-- Run in Render.com PostgreSQL console

BEGIN;

-- First, find HR Manager user ID
-- Note: Adjust the WHERE clause based on your HR Manager username/department

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

