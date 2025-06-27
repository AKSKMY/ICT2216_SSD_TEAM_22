import os
import re
from dotenv import load_dotenv

from backend.app import app
from backend.routes.init import register_blueprints

load_dotenv()

register_blueprints(app)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = app.config.get("DEBUG", False)
    app.run(debug=debug_mode, host="0.0.0.0", port=port)