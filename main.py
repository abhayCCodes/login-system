import json
import os
import re
import bcrypt
from typing import Dict, Any, List

# ---------- User Class ----------
class User:
    def __init__(self, username: str, password: str, role: str = "user", subordinates: List[str] = None) -> None:
        self.username = username
        self.password = self.hash_password(password)  # store hashed password
        self.role = role
        self.subordinates = subordinates or []

    @classmethod
    def from_dict(cls, username: str, data: Dict[str, Any]) -> "User":
        """For LOADED users: Uses pre-hashed passwords."""
        user = cls(username, "dummy", data["role"], data.get("subordinates", []))
        user.password = data["password"]  # ← Pre-hashed (no re-hashing)
        return user

    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()    

    @staticmethod #if we use@staticmethos, then we don’t need to create or mention the user object in that class, we use it for special tasks
    def is_strong_password(password: str) -> bool:
        # Validate password strength rules
        return (len(password) >= 8 
                and re.search(r"[A-Z]", password) 
                and re.search(r"\d", password) 
                and re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
              
    def check_password(self, input_password: str) -> bool:
        return bcrypt.checkpw(input_password.encode(), self.password.encode())    

    def to_dict(self) -> Dict[str, Any]:
        return {
            "password": self.password,
            "role": self.role,
            "subordinates": self.subordinates
        }

# ---------- User File Manager ----------
class UserManager:
    def __init__(self, filepath: str = "users.json"):
        self.filepath = filepath
        self.users: Dict[str, User] = self.load_users()

    def load_users(self) -> Dict[str, User]:
        if not os.path.exists(self.filepath):
            return{}
        
        try:
            with open(self.filepath, "r") as file:
                data = json.load(file)
                return {
                    username: User.from_dict(username, user_data) 
                    for username, user_data in data.items() 
                    if isinstance(user_data, dict) and all(
                        key in user_data for key in ["password", "role"]
                    )  
                }      
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading users: {e}")
            return {}
    
    def save_users(self):
        with open(self.filepath, "w") as file:
            json.dump({u: self.users[u].to_dict() for u in self.users}, file, indent=4)

    def add_user(self, user: User):
        self.users[user.username] = user
        self.save_users()

    def get_user(self, username: str) -> User:
        return self.users.get(username)

    def delete_user(self, username: str):
        if username in self.users:
            del self.users[username]
            self.save_users()

# ---------- Auth System ----------
class AuthSystem:
    def __init__(self):
        self.user_manager = UserManager()
        self.login_attempts: Dict[str, int] = {}
        self.max_attempts = 3

    def get_valid_password(self, username: str) -> str:
        while True:
            password = input("Enter password: ").strip()
            if User.is_strong_password(password):
                return password
            print("Weak password for user %s. Must be at least 8 chars with an uppercase, a number, and special char.", username)

    def register(self):
        username = input("Enter username: ").strip()
        if not re.match(r"^[a-zA-Z0-9_]+$", username):
            print(f"Username must be 3+ alphanumeric (letters, numbers, underscores only).")
            return
        if self.user_manager.get_user(username):
            print(f"Username already exists.")
            return

        role = input("Enter role (admin/user): ").strip().lower()
        if role not in ["admin", "user"]:
            print("Invalid role. Must be 'admin' or 'user'.")
            return
        password = self.get_valid_password(username)
        user = User(username, password, role)

        if role == "admin":
            sub = input("Enter subordinate username (or leave blank): ").strip()
            if sub and self.user_manager.get_user(sub):
                user.subordinates.append(sub)

        self.user_manager.add_user(user)
        print("User registered successfully.")

    def login(self):
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        user = self.user_manager.get_user(username)

        # Track login attempts
        if self.login_attempts.get(username, 0) >= self.max_attempts:
            print("Account locked due to too many attempts.")
            return

        if user and user.check_password(password):
            print(f"Welcome {username}!")
            self.login_attempts[username] = 0  # reset on success
        else:
            self.login_attempts[username] = self.login_attempts.get(username, 0) + 1
            remaining = self.max_attempts - self.login_attempts[username]
            print(f"Invalid login. Attempts left: {remaining}")

    def forgot_password(self):
        username = input("Enter your username: ").strip()
        user = self.user_manager.get_user(username)
        if user:
            while True:
                new_password = input("Enter new password: ").strip()
                if User.is_strong_password(new_password):
                    user.password = User.hash_password(new_password)
                    self.user_manager.save_users()
                    print("Password reset successful.")
                    break
                else:
                    print("Weak password. Try again.")
        else:
            print("Username not found.")

    def delete_user(self):
        username = input("Username to delete: ").strip()
        confirm = input("Are you sure? (yes/no): ").lower()
        if confirm == "yes":
            self.user_manager.delete_user(username)
            print("User deleted.")

    def show_users(self):
        for username, user in self.user_manager.users.items():
            print(f"- {username} ({user.role})")
            for sub in user.subordinates:
                print(f"   \__ {sub}")

# ---------- Main Loop ----------
def main():
    system = AuthSystem()
    while True:
        print("\n1. Register\n2. Login\n3. Forgot Password\n4. Delete User\n5. Show Users\n6. Exit")
        choice = input("Choose: ")
        if choice == "1":
            system.register()
        elif choice == "2":
            system.login()
        elif choice == "3":
            system.forgot_password()
        elif choice == "4":
            system.delete_user()
        elif choice == "5":
            system.show_users()
        elif choice == "6":
            break
        else:
            print("Invalid option.")

if __name__ == "__main__":
    main()
