import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"

# Put src/ at the front of sys.path so "web_security_tool" can be imported
sys.path.insert(0, str(SRC))

from web_security_tool.main import WebSecurityTool

if __name__ == "__main__":
    app = WebSecurityTool()
    app.mainloop()
