from flask import Flask, render_template, request, jsonify
from recon.lookup import run_all

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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
