“””
Flask API — wraps the offline engine.
Zero external AI calls.
“””

import os, base64, uuid
from flask import Flask, request, jsonify
from flask_cors import CORS
from engine import analyze
from report import generate_docx

app = Flask(**name**)
CORS(app)

OUTPUT_DIR = “/tmp/threat_outputs”
os.makedirs(OUTPUT_DIR, exist_ok=True)

@app.route(”/health”)
def health():
return jsonify({“status”: “ok”, “mode”: “offline”})

@app.route(”/analyze”, methods=[“POST”])
def analyze_route():
try:
data = request.get_json(force=True)
b64 = data.get(“image”, “”)
if “,” in b64:
b64 = b64.split(”,”, 1)[1]
image_bytes = base64.b64decode(b64)

```
    result = analyze(image_bytes)

    # Generate Word report
    report_id = uuid.uuid4().hex[:10]
    report_path = f"{OUTPUT_DIR}/threat_report_{report_id}.docx"
    generate_docx(result, report_path)

    with open(report_path, "rb") as f:
        docx_b64 = base64.b64encode(f.read()).decode()

    anon_b64 = base64.b64encode(result["anonymized_image_bytes"]).decode()

    return jsonify({
        "success": True,
        "anonymized_image": f"data:image/png;base64,{anon_b64}",
        "components": result["components"],
        "stride": result["stride"],
        "overall_risk": result["overall_risk"],
        "recommendations": result["recommendations"],
        "mapping": result["mapping"],
        "threat_count": result["threat_count"],
        "docx_b64": docx_b64,
        "docx_filename": f"threat_report_{report_id}.docx",
    })

except Exception as e:
    import traceback
    return jsonify({"error": str(e), "trace": traceback.format_exc()}), 500
```

if **name** == “**main**”:
print(“🛡️  Arch Threat Modeler — offline mode (no AI API)”)
app.run(host=“0.0.0.0”, port=5050, debug=False)
