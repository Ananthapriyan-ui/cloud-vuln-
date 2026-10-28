import importlib
import os
import sys

# Add root and backend directories to sys.path so all backend imports resolve
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_dir = os.path.join(root_dir, "backend")

for d in (backend_dir, root_dir):
    if d not in sys.path:
        sys.path.insert(0, d)

try:
    _main_module = importlib.import_module("backend.main")
except ImportError:
    _main_module = importlib.import_module("main")

# Export for both ASGI (app) and serverless function handlers
app = getattr(_main_module, "app")
handler = app
