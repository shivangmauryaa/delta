from flask import Flask, request, jsonify
from flask_cors import CORS
import requests

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # allow all origins

@app.route("/api/open-redirect", methods=["POST"])
def open_redirect():
    try:
        data = request.json
        base_url = data.get("url")
        if not base_url:
            return jsonify({"error": "No URL provided"}), 400

        # Common open redirect payloads
        payloads = [
            "//evil.com",
            "/@evil.com",
            "https://evil.com",
            "http://evil.com",
            "////evil.com",
            "///evil.com"
        ]

        results = []
        for p in payloads:
            # If URL already has ?, assume query param
            if "?" in base_url:
                test_url = f"{base_url}{p}"
            else:
                test_url = f"{base_url.rstrip('/')}/{p}"

            try:
                resp = requests.get(test_url, timeout=5, allow_redirects=False)
                if "evil.com" in resp.headers.get("Location", ""):
                    results.append({"payload": p, "url": test_url, "status": "Possible Redirect"})
                else:
                    results.append({"payload": p, "url": test_url, "status": "Safe"})
            except Exception as e:
                results.append({"payload": p, "url": test_url, "status": f"Error: {str(e)}"})

        return jsonify({"results": results})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
