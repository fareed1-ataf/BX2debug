import os

readme = '''# BX2debug

BX2debug is an advanced behavioral malware analysis CLI tool built on top of the BX2trace framework.
It provides real-time monitoring of process creation, API hooking, live memory scanning, and string extraction.

## Installation

1. Install the core library:
   `ash
   pip install BX2trace
   `
2. Run the tool:
   `ash
   python main.py -t <target.exe>
   `
'''

with open("README.md", "w") as f:
    f.write(readme)

gitignore = '''__pycache__/
*.pyc
reports/
logs/
.venv/
venv/
'''

with open(".gitignore", "w") as f:
    f.write(gitignore)

print("Files written successfully")
