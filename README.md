# login-system
A simple Python login and registration system using OOP, bcrypt, and JSON.
# Features
User registration with role (admin/user)
Password validation: minimum 8 chars, uppercase, number, special char
Passwords are hashed using `bcrypt` (secure storage)
Forgot password support
Login attempt limit (locks after 3 failures)
Admin can assign subordinates
JSON file storage (no SQL setup needed)
Async login with `asyncio` for multi-user simulation
Object-Oriented Programming structure for clean code
Developed while learning Python, with support from AI tools like ChatGPT for clarity and code structure.
# How to run
1. Make sure you have Python installed (version 3.6 or higher).
2. Install required dependencies:
```bash
pip install -r requirements.txt
3. Run the application:
```bash
python main.py
# Author
Abhay Chauhan
Learning full-stack development through practical coding projects.



