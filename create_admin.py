#!/usr/bin/env python3.12
"""
Create Admin User Script for Vidnag Framework

This standalone script creates an admin user account in the database.
Run this after initial setup to create your first admin user.

Usage:
    python3.12 create_admin.py

The script will prompt for username and password interactively.
"""

import sys
import getpass
import re
from datetime import datetime, timezone

# Import database and authentication modules
from database import init_db, get_db
from auth import PasswordService, AuditLogService


def validate_username(username):
    """
    Validate username format.

    Requirements:
    - 3-32 characters long
    - Alphanumeric and underscores only

    Args:
        username: Username to validate

    Returns:
        (is_valid, error_message)
    """
    if not username:
        return False, "Username cannot be empty"

    if len(username) < 3:
        return False, "Username must be at least 3 characters long"

    if len(username) > 32:
        return False, "Username must be at most 32 characters long"

    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username must contain only alphanumeric characters and underscores"

    return True, None


def validate_password(password):
    """
    Validate password strength.

    Requirements:
    - At least 8 characters long

    Args:
        password: Password to validate

    Returns:
        (is_valid, error_message)
    """
    if not password:
        return False, "Password cannot be empty"

    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    return True, None


def check_user_exists(db, username):
    """
    Check if a user with the given username already exists.

    Args:
        db: Database session
        username: Username to check

    Returns:
        bool: True if user exists, False otherwise
    """
    from database import User
    existing_user = db.query(User).filter(User.username == username).first()
    return existing_user is not None


def create_admin_user():
    """
    Main function to create an admin user.
    Prompts for username and password, validates input, and creates the user.
    """
    print("=" * 60)
    print("Vidnag Framework - Create Admin User")
    print("=" * 60)
    print()

    # Ensure database is initialized
    print("Initializing database...")
    init_db()
    print("✓ Database initialized")
    print()

    # Get username
    while True:
        username = input("Enter admin username: ").strip()

        # Validate username
        is_valid, error_msg = validate_username(username)
        if not is_valid:
            print(f"✗ {error_msg}")
            print()
            continue

        # Check if user already exists
        with get_db() as db:
            if check_user_exists(db, username):
                print(f"✗ User '{username}' already exists")
                print()
                choice = input("Do you want to try a different username? (y/n): ").strip().lower()
                if choice != 'y':
                    print("Aborted.")
                    return 1
                continue

        break

    print()

    # Get password
    while True:
        password = getpass.getpass("Enter admin password: ")

        # Validate password
        is_valid, error_msg = validate_password(password)
        if not is_valid:
            print(f"✗ {error_msg}")
            print()
            continue

        # Confirm password
        password_confirm = getpass.getpass("Confirm password: ")
        if password != password_confirm:
            print("✗ Passwords do not match")
            print()
            continue

        break

    print()

    # Create user
    print("Creating admin user...")
    try:
        with get_db() as db:
            from database import User

            # Hash password
            password_hash = PasswordService.hash_password(password)

            # Create user
            admin_user = User(
                username=username,
                password_hash=password_hash,
                is_admin=True,
                is_disabled=False
            )

            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)

            # Log audit event
            AuditLogService.log_event(
                event_type="user_created",
                ip_address="127.0.0.1",
                db=db,
                user_id=admin_user.id,
                username=username,
                details={
                    "created_by": "create_admin.py script",
                    "is_admin": True
                }
            )

            print()
            print("=" * 60)
            print("✓ Admin user created successfully!")
            print("=" * 60)
            print()
            print(f"Username: {username}")
            print(f"User ID:  {admin_user.id}")
            print(f"Admin:    Yes")
            print(f"Created:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print()
            print("You can now login at: http://your-server/assets/login.html")
            print()
            print("IMPORTANT: Enable authentication in admin_settings.json:")
            print('  Set "auth": { "enabled": true }')
            print()

            return 0

    except Exception as e:
        print()
        print(f"✗ Failed to create admin user: {str(e)}")
        print()
        return 1


if __name__ == "__main__":
    try:
        sys.exit(create_admin_user())
    except KeyboardInterrupt:
        print()
        print()
        print("Aborted by user.")
        sys.exit(1)
    except Exception as e:
        print()
        print(f"✗ Unexpected error: {str(e)}")
        sys.exit(1)
