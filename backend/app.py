from flask import Flask, send_from_directory
import os

project_root = os.path.dirname(os.path.abspath(__file__))
html_folder = os.path.join(project_root, "../html")

app = Flask(__name__, static_folder=html_folder, static_url_path='')

@app.route("/")
def serve_index():
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
