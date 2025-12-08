#!/usr/bin/env python3
"""
Script to create users for the portal
"""
import sys
import os
import getpass

# Add main directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Core.auth_manager import AuthManager
from Utils.logger import get_logger

def main():
    """Main function"""
    print("\n" + "="*50)
    print("USER CREATOR - CAPTIVE PORTAL")
    print("="*50)
    
    if len(sys.argv) < 2:
        print("\nUsage: python create_user.py <username>")
        print("Example: python create_user.py admin\n")
        sys.exit(1)
    
    username = sys.argv[1]
    
    # Get password
    print(f"\nCreating user: {username}")
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    
    if password != confirm:
        print("\n❌ Passwords do not match")
        sys.exit(1)
    
    if len(password) < 6:
        print("\n❌ Password must be at least 6 characters")
        sys.exit(1)
    
    # Create user
    auth_manager = AuthManager()
    
    if auth_manager.create_user(username, password):
        print(f"\n✅ User '{username}' created successfully")
        
        # Log
        logger = get_logger()
        logger.success(f"User '{username}' created")
    else:
        print(f"\n❌ User '{username}' already exists")
        sys.exit(1)

if __name__ == "__main__":
    main()