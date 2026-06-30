from flask import Flask, render_template, request, jsonify
from recon.lookup import run_all, resolve_target
from recon.portscan import run_scan
from recon.dns_enum import run_dns_enum
from recon.ssl_inspect import inspect as ssl_inspect

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/recon", methods=["POST"])
def recon():
    data = request.get_json()
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    results = run_all(target)
    return jsonify(results)


@app.route("/api/portscan", methods=["POST"])
def portscan():
    data = request.get_json()
    target = (data.get("target") or "").strip()
    ports = (data.get("ports") or "common").strip()
    timeout = float(data.get("timeout") or 1.0)
    if not target:
        return jsonify({"error": "No target provided"}), 400
    resolved = resolve_target(target)
    if resolved["error"]:
        return jsonify({"error": resolved["error"]}), 400
    results = run_scan(resolved["ip"], ports, timeout)
    results["target"] = target
    results["ip"] = resolved["ip"]
    return jsonify(results)


@app.route("/api/dnsenum", methods=["POST"])
def dnsenum():
    data = request.get_json()
    target = (data.get("target") or "").strip()
    brute = data.get("brute", True)
    wordlist = (data.get("wordlist") or "small").strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400
    # Strip to domain only (drop scheme/path if pasted as URL)
    target = target.replace("https://", "").replace("http://", "").split("/")[0]
    results = run_dns_enum(target, brute=brute, wordlist=wordlist)
    return jsonify(results)


@app.route("/api/sslinspect", methods=["POST"])
def sslinspect():
    data = request.get_json()
    target = (data.get("target") or "").strip().replace("https://", "").replace("http://", "").split("/")[0]
    port = int(data.get("port") or 443)
    if not target:
        return jsonify({"error": "No target provided"}), 400
    result = ssl_inspect(target, port)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
