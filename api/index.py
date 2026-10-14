import os
import sys

# Add root and backend directories to sys.path so all backend imports resolve
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(root_dir, "backend")

for d in (backend_dir, root_dir):
    if d not in sys.path:
        sys.path.insert(0, d)

try:
    from backend.main import app
except ImportError:
    from main import app

# Export for both ASGI (app) and serverless function handlers
app = app
handler = app
