#!/usr/bin/env python3
"""CLI tool to manage socai web users (config/users.json)."""
import argparse
import getpass
import json
import sys
from datetime import date
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.auth import hash_password, load_users, save_users

VALID_ROLES = ("admin", "analyst", "viewer")
ALL_PERMISSIONS = [
    "investigations:submit",
    "investigations:read",
    "campaigns:read",
    "ioc_index:read",
]

ROLE_PERMISSIONS = {
    "admin": ["admin"],
    "analyst": ["investigations:submit", "investigations:read", "campaigns:read", "ioc_index:read"],
    "viewer": ["investigations:read", "campaigns:read", "ioc_index:read"],
}


def cmd_add(args):
    users = load_users()
    if args.email in users:
        print(f"User {args.email} already exists. Use 'reset-password' to change password.")
        sys.exit(1)
    password = args.password or getpass.getpass("Password: ")
    if len(password) < 8:
        print("Password must be at least 8 characters.")
        sys.exit(1)
    role = args.role
    users[args.email] = {
        "password_hash": hash_password(password),
        "role": role,
        "active": True,
        "created": str(date.today()),
        "permissions": ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["viewer"]),
    }
    save_users(users)
    print(f"Added user {args.email} (role={role})")


def cmd_remove(args):
    users = load_users()
    if args.email not in users:
        print(f"User {args.email} not found.")
        sys.exit(1)
    del users[args.email]
    save_users(users)
    print(f"Removed user {args.email}")


def cmd_list(args):
    users = load_users()
    if not users:
        print("No users configured.")
        return
    for email, data in users.items():
        status = "active" if data.get("active") else "disabled"
        print(f"  {email}  role={data.get('role')}  {status}  created={data.get('created')}")


def cmd_reset_password(args):
    users = load_users()
    if args.email not in users:
        print(f"User {args.email} not found.")
        sys.exit(1)
    password = args.password or getpass.getpass("New password: ")
    if len(password) < 8:
        print("Password must be at least 8 characters.")
        sys.exit(1)
    users[args.email]["password_hash"] = hash_password(password)
    save_users(users)
    print(f"Password reset for {args.email}")


def cmd_disable(args):
    users = load_users()
    if args.email not in users:
        print(f"User {args.email} not found.")
        sys.exit(1)
    users[args.email]["active"] = False
    save_users(users)
    print(f"Disabled user {args.email}")


def cmd_enable(args):
    users = load_users()
    if args.email not in users:
        print(f"User {args.email} not found.")
        sys.exit(1)
    users[args.email]["active"] = True
    save_users(users)
    print(f"Enabled user {args.email}")


def main():
    parser = argparse.ArgumentParser(description="Manage socai web users")
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Add a new user")
    p_add.add_argument("--email", required=True)
    p_add.add_argument("--role", choices=VALID_ROLES, default="analyst")
    p_add.add_argument("--password", help="Password (prompted if omitted)")
    p_add.set_defaults(func=cmd_add)

    p_rm = sub.add_parser("remove", help="Remove a user")
    p_rm.add_argument("--email", required=True)
    p_rm.set_defaults(func=cmd_remove)

    p_ls = sub.add_parser("list", help="List all users")
    p_ls.set_defaults(func=cmd_list)

    p_rp = sub.add_parser("reset-password", help="Reset user password")
    p_rp.add_argument("--email", required=True)
    p_rp.add_argument("--password", help="New password (prompted if omitted)")
    p_rp.set_defaults(func=cmd_reset_password)

    p_dis = sub.add_parser("disable", help="Disable a user")
    p_dis.add_argument("--email", required=True)
    p_dis.set_defaults(func=cmd_disable)

    p_en = sub.add_parser("enable", help="Enable a user")
    p_en.add_argument("--email", required=True)
    p_en.set_defaults(func=cmd_enable)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
