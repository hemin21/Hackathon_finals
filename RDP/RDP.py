import subprocess

# Take user input from the terminal
ip = input("Enter IP Address: ")
username = input("Enter Username: ")
password = input("Enter Password: ")

# Construct the xfreerdp command with user input
command = f"xfreerdp /u:{username} /p:{password} /v:{ip} /dynamic-resolution +cert-ignore"

# Run the command
try:
    subprocess.run(command, shell=True)  # Run xfreerdp in the terminal
except Exception as e:
    print(f"Error: {e}")
