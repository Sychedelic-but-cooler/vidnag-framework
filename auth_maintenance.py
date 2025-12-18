import sys
import getpass
from datetime import datetime, timezone, timedelta

from database import init_db, get_db, User, FailedLoginAttempt, AuthAuditLog
from auth import PasswordService, AuthService


def unlock_user(username):
    # Enables the account and clears all failed login attempts. 
    # Clearing failures allows the user more grace to prevent immediate re-locking.
    print(f"Unlocking account: {username}")
    print()

    try:
        with get_db() as db:
            user = db.query(User).filter(User.username == username).first()
            if not user:
                print(f"✗ User '{username}' not found")
                return 1

            # Enable account
            was_disabled = user.is_disabled
            user.is_disabled = False
            user.updated_at = datetime.now(timezone.utc)

            # Clear failed login attempts
            AuthService.clear_failed_attempts(username, db)

            db.commit()

            print(f"✓ Account '{username}' unlocked successfully")
            if was_disabled:
                print("  - Account re-enabled")
            print("  - Failed login attempts cleared")
            print()

            return 0

    except Exception as e:
        print(f"✗ Failed to unlock account: {str(e)}")
        return 1


def reset_password(username):
    # Reset a user's password. Prompts for new password and updates the user's password hash.
    print(f"Resetting password for: {username}")
    print()

    try:
        with get_db() as db:
            user = db.query(User).filter(User.username == username).first()
            if not user:
                print(f"✗ User '{username}' not found")
                return 1

            # Get new password
            while True:
                password = getpass.getpass("Enter new password (min 8 characters): ")

                if len(password) < 8:
                    print("✗ Password must be at least 8 characters long")
                    continue

                password_confirm = getpass.getpass("Confirm new password: ")
                if password != password_confirm:
                    print("✗ Passwords do not match")
                    continue

                break

            # Update password
            user.password_hash = PasswordService.hash_password(password)
            user.updated_at = datetime.now(timezone.utc)
            db.commit()

            print()
            print(f"✓ Password reset successfully for '{username}'")
            print()

            return 0

    except Exception as e:
        print(f"✗ Failed to reset password: {str(e)}")
        return 1


def cleanup_old_logs(days):
    # Remove audit logs older than N days, older entries are deleted.
    try:
        days = int(days)
        if days < 1:
            print("✗ Days must be a positive number")
            return 1
    except ValueError:
        print("✗ Days must be a valid number")
        return 1

    print(f"Cleaning up audit logs older than {days} days...")
    print()

    try:
        with get_db() as db:
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)

            # Count logs to delete
            old_logs = db.query(AuthAuditLog).filter(
                AuthAuditLog.timestamp < cutoff
            ).count()

            if old_logs == 0:
                print(f"✓ No logs older than {days} days found")
                return 0

            # Confirm deletion
            print(f"Found {old_logs} audit log entries older than {days} days")
            confirm = input("Delete these entries? (yes/no): ").strip().lower()

            if confirm != 'yes':
                print("Cancelled")
                return 0

            # Delete old logs
            db.query(AuthAuditLog).filter(
                AuthAuditLog.timestamp < cutoff
            ).delete()
            db.commit()

            print()
            print(f"✓ Deleted {old_logs} old audit log entries")
            print()

            return 0

    except Exception as e:
        print(f"✗ Failed to cleanup logs: {str(e)}")
        return 1


def list_locked_accounts():
    # Show all disabled accounts.
    print("Locked/Disabled Accounts")
    print("=" * 80)
    print()

    try:
        with get_db() as db:
            locked_users = db.query(User).filter(
                User.is_disabled == True
            ).order_by(User.username).all()

            if not locked_users:
                print("No locked accounts found")
                print()
                return 0

            for user in locked_users:
                print(f"Username:    {user.username}")
                print(f"User ID:     {user.id}")
                print(f"Admin:       {'Yes' if user.is_admin else 'No'}")
                print(f"Created:     {user.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                if user.last_login:
                    print(f"Last Login:  {user.last_login.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                else:
                    print(f"Last Login:  Never")
                print("-" * 80)

            print()
            print(f"Total: {len(locked_users)} locked account(s)")
            print()

            return 0

    except Exception as e:
        print(f"✗ Failed to list locked accounts: {str(e)}")
        return 1


def list_users():
    # Show all user accounts.
    print("All User Accounts")
    print("=" * 80)
    print()

    try:
        with get_db() as db:
            users = db.query(User).order_by(User.username).all()

            if not users:
                print("No users found")
                print()
                return 0

            for user in users:
                status = "🔒 LOCKED" if user.is_disabled else "✓ Active"
                admin_badge = " [ADMIN]" if user.is_admin else ""

                print(f"{status}  {user.username}{admin_badge}")
                print(f"         User ID:     {user.id}")
                print(f"         Created:     {user.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                if user.last_login:
                    print(f"         Last Login:  {user.last_login.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                else:
                    print(f"         Last Login:  Never")
                print()

            print(f"Total: {len(users)} user(s)")
            print()

            return 0

    except Exception as e:
        print(f"✗ Failed to list users: {str(e)}")
        return 1


def delete_user(username):
    # Delete a user account. Requires confirmation before deletion.
    print(f"Delete user account: {username}")
    print()

    try:
        with get_db() as db:
            user = db.query(User).filter(User.username == username).first()
            if not user:
                print(f"✗ User '{username}' not found")
                return 1

            # Show user info
            print(f"User ID:     {user.id}")
            print(f"Username:    {user.username}")
            print(f"Admin:       {'Yes' if user.is_admin else 'No'}")
            print(f"Disabled:    {'Yes' if user.is_disabled else 'No'}")
            print(f"Created:     {user.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            print()

            # Confirm deletion
            print("⚠️  WARNING: This action cannot be undone!")
            confirm = input(f"Type '{username}' to confirm deletion: ").strip()

            if confirm != username:
                print("Cancelled - username did not match")
                return 0

            # Delete associated records
            db.query(FailedLoginAttempt).filter(
                FailedLoginAttempt.username == username
            ).delete()

            # Delete user
            db.delete(user)
            db.commit()

            print()
            print(f"✓ User '{username}' deleted successfully")
            print()

            return 0

    except Exception as e:
        print(f"✗ Failed to delete user: {str(e)}")
        return 1


def print_usage():
    # Print usage information.
    print(__doc__)


def main():
    # Main entry point.
    if len(sys.argv) < 2:
        print_usage()
        return 1

    # Initialize database
    init_db()

    command = sys.argv[1]

    if command == "unlock-user":
        if len(sys.argv) < 3:
            print("✗ Usage: auth_maintenance.py unlock-user <username>")
            return 1
        return unlock_user(sys.argv[2])

    elif command == "reset-password":
        if len(sys.argv) < 3:
            print("✗ Usage: auth_maintenance.py reset-password <username>")
            return 1
        return reset_password(sys.argv[2])

    elif command == "cleanup-old-logs":
        if len(sys.argv) < 3:
            print("✗ Usage: auth_maintenance.py cleanup-old-logs <days>")
            return 1
        return cleanup_old_logs(sys.argv[2])

    elif command == "list-locked-accounts":
        return list_locked_accounts()

    elif command == "list-users":
        return list_users()

    elif command == "delete-user":
        if len(sys.argv) < 3:
            print("✗ Usage: auth_maintenance.py delete-user <username>")
            return 1
        return delete_user(sys.argv[2])

    else:
        print(f"✗ Unknown command: {command}")
        print()
        print_usage()
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        print()
        print("Aborted by user.")
        sys.exit(1)
    except Exception as e:
        print()
        print(f"✗ Unexpected error: {str(e)}")
        sys.exit(1)
