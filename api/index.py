import os
import sys

# Add backend directory to sys.path so all backend imports (models, schemas, config, etc.) resolve
backend_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

try:
    from backend.main import app
except ImportError:
    from main import app

# Export for Vercel Serverless Function runtime
handler = app
