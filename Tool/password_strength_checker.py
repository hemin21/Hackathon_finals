import os
import sys
import subprocess
import re
try:
    from zxcvbn import zxcvbn
except ImportError:
    print("\n[🔧] Setting up the environment...")
    
    # Step 1: Create Virtual Environment if not exists
    if not os.path.exists("venv"):
        subprocess.run([sys.executable, "-m", "venv", "venv"])

    # Step 2: Install Dependencies
    subprocess.run(["venv/bin/python", "-m", "pip", "install", "--upgrade", "pip"])
    subprocess.run(["venv/bin/python", "-m", "pip", "install", "zxcvbn"])

    # Step 3: Restart the Script with Virtual Environment Python
    os.execv("venv/bin/python", ["venv/bin/python"] + sys.argv)

# Clear screen function
def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

# Function to check password strength
def check_password_strength():
    password = input("\n🔑 Enter password to check: ")
    
    if len(password) < 12:
        print("\n[❌] Too short: Password should be at least 12 characters long.")
        return
    
    if not re.search(r"[A-Z]", password):
        print("\n[❌] Weak: Include at least one uppercase letter.")
        return

    if not re.search(r"[a-z]", password):
        print("\n[❌] Weak: Include at least one lowercase letter.")
        return

    if not re.search(r"[0-9]", password):
        print("\n[❌] Weak: Include at least one number.")
        return

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        print("\n[❌] Weak: Include at least one special character.")
        return

    strength = zxcvbn(password)
    print(f"\n[✅] Strength Score: {strength['score']}/4")
    print(f"📝 Feedback: {strength['feedback']['suggestions']}")

# Function to generate a strong password
def generate_password():
    import secrets
    import string
    length = 16
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    strong_password = "".join(secrets.choice(characters) for _ in range(length))
    print(f"\n[🔐] Generated Strong Password: {strong_password}")

# Main Menu
def main():
    while True:
        clear_screen()
        print("\n[🔹] Password Strength Checker")
        print("1️⃣  Check Password Strength")
        print("2️⃣  Generate Strong Password")
        print("3️⃣  Exit")

        choice = input("\nEnter your choice (1-3): ")

        if choice == "1":
            check_password_strength()
        elif choice == "2":
            generate_password()
        elif choice == "3":
            print("\n[👋] Exiting...")
            break
        else:
            print("\n[⚠] Invalid choice! Try again.")

        input("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
