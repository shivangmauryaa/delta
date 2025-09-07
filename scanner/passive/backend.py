# backend.py

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS  # Import CORS
import requests

app = Flask(__name__)
CORS(app)  # Enable CORS for your entire app

@app.route("/")
def home():
    return send_from_directory(".", "index.html")

@app.route("/api/passive-links", methods=["POST"])
def passive_links():
    data = request.get_json()
    domain = data.get("domain")
    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey"

    try:
        # It's good practice to add a user-agent
        headers = {'User-Agent': 'PassiveLinkFinder/1.0'}
        r = requests.get(url, headers=headers, timeout=25)
        
        # Raise an exception for bad status codes like 4xx or 5xx
        r.raise_for_status()

        links = r.text.strip().split("\n")
        
        # Handle cases where the API returns an empty string or just whitespace
        if not links or (len(links) == 1 and not links[0]):
             return jsonify({"results": []})

        return jsonify({"results": links})

    except requests.exceptions.RequestException as e:
        # Catch specific request-related errors
        return jsonify({"error": f"Failed to fetch from Wayback: {e}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(port=5000, debug=True)
