import os
import subprocess
import pyfiglet

# Path where tools are stored
TOOLS_DIR = "Tool/"

# Tools List (Extracted from your GitHub screenshot)
TOOLS = [
    "Cupp.py",
    "CyberSniffer.py",
    "Ddos.py",
    "File_Transfer.sh",
    "RDP.py",
    "Secure_fileshare.py",
    "URL_Inspect.py",
    "password_strength_checker.py",
    "phishing_Detector.py"
]

def display_banner():
    os.system("clear" if os.name == "posix" else "cls")
    banner_text = pyfiglet.figlet_format("CodeWave Crew", font="slant")
    print(f"\033[92m{banner_text}\033[0m")
    print("[X] Toolkit - Ethical Hacking Suite [X]\n")
    print("⚠ Use responsibly for security research & educational purposes only.\n")

# Run commands in a new terminal
def open_terminal(command):
    try:
        if os.name == "posix":  # Linux/macOS
            subprocess.Popen(["gnome-terminal", "--", "bash", "-c", f"{command}; exec bash"])
        else:  # Windows
            subprocess.Popen(["cmd.exe", "/c", "start", "cmd.exe", "/k", command])
    except Exception as e:
        print(f"❌ ERROR: Failed to open terminal -> {e}")

# Install tool (Assumes `--install` flag is supported)
def install_tool(tool_name):
    tool_path = os.path.join(TOOLS_DIR, tool_name)
    install_command = f"python3 {tool_path} --install" if tool_name.endswith(".py") else f"bash {tool_path} --install"
    
    print(f"🔧 Installing {tool_name}... (Opening new terminal)")
    open_terminal(install_command)

# Run tool normally
def run_tool(tool_name):
    tool_path = os.path.join(TOOLS_DIR, tool_name)
    run_command = f"python3 {tool_path}" if tool_name.endswith(".py") else f"bash {tool_path}"
    
    print(f"🚀 Running {tool_name}... (Opening new terminal)")
    open_terminal(run_command)

# Main menu
def main_menu():
    while True:
        display_banner()

        print("\nAvailable Tools:")
        for i, tool in enumerate(TOOLS, start=1):
            print(f"[{i}] {tool}")

        print(f"[{len(TOOLS) + 1}] Exit")

        try:
            choice = int(input("\nChoose a tool: "))
            if 1 <= choice <= len(TOOLS):
                tool_name = TOOLS[choice - 1]
                tool_options(tool_name)
            elif choice == len(TOOLS) + 1:
                print("🔚 Exiting Toolkit...")
                break
            else:
                print("❌ Invalid choice! Enter a valid number.")
        except ValueError:
            print("❌ Invalid input! Please enter a number.")

# Tool-specific menu
def tool_options(tool_name):
    while True:
        print(f"\n🔹 [{tool_name}]\n[1] Install {tool_name}\n[2] Run {tool_name}\n[3] Back to Main Menu")
        try:
            choice = int(input("\nChoose an option: "))
            if choice == 1:
                install_tool(tool_name)
            elif choice == 2:
                run_tool(tool_name)
            elif choice == 3:
                break
            else:
                print("❌ Invalid choice! Enter a valid option.")
        except ValueError:
            print("❌ Invalid input! Please enter a number.")

# Start the script
if __name__ == "__main__":
    main_menu()
