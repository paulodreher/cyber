import { useState, useRef, useCallback } from “react”;

const API = “http://localhost:5050”;

const RISK_STYLE = {
critical: { bg: “#FFF0F0”, border: “#C00000”, text: “#C00000” },
high:     { bg: “#FFF4F0”, border: “#E74C3C”, text: “#E74C3C” },
medium:   { bg: “#FFFBF0”, border: “#ED7D31”, text: “#ED7D31” },
low:      { bg: “#F0FFF4”, border: “#70AD47”, text: “#70AD47” },
};

const STRIDE_META = [
{ key: “Spoofing”,               icon: “🎭”, label: “Spoofing (S)”,               color: “#7B2FBE” },
{ key: “Tampering”,              icon: “🔧”, label: “Tampering (T)”,              color: “#C0392B” },
{ key: “Repudiation”,            icon: “📋”, label: “Repudiation (R)”,            color: “#2980B9” },
{ key: “Information Disclosure”, icon: “🔓”, label: “Information Disclosure (I)”, color: “#E67E22” },
{ key: “Denial of Service”,      icon: “🚫”, label: “Denial of Service (D)”,      color: “#E74C3C” },
{ key: “Elevation of Privilege”, icon: “⬆️”, label: “Elevation of Privilege (E)”, color: “#8E44AD” },
];

const TABS = [“Overview”, “STRIDE”, “Recommendations”, “Anon Map”];

function Badge({ risk }) {
const s = RISK_STYLE[risk] || RISK_STYLE.low;
return (
<span style={{
display: “inline-block”, padding: “2px 9px”, borderRadius: 10,
background: s.bg, color: s.text, border: `1px solid ${s.border}`,
fontWeight: 700, fontSize: 10, letterSpacing: 1, textTransform: “uppercase”,
}}>{risk}</span>
);
}

function ThreatTable({ meta, items }) {
if (!items?.length) return null;
return (
<div style={{ marginBottom: 28 }}>
<div style={{ display: “flex”, alignItems: “center”, gap: 8, marginBottom: 10 }}>
<span style={{ fontSize: 18 }}>{meta.icon}</span>
<span style={{ fontWeight: 700, fontSize: 14, color: meta.color }}>{meta.label}</span>
<span style={{
background: meta.color + “22”, color: meta.color,
padding: “1px 8px”, borderRadius: 10, fontSize: 11, fontWeight: 600
}}>{items.length}</span>
</div>
<div style={{ overflowX: “auto”, borderRadius: 8, border: “1px solid #e2e8f0” }}>
<table style={{ width: “100%”, borderCollapse: “collapse”, fontSize: 12 }}>
<thead>
<tr style={{ background: “#1F3864” }}>
{[“Component”, “Threat”, “Risk”, “Mitigation”, “CWE”, “Ref”].map(h => (
<th key={h} style={{ padding: “8px 10px”, color: “#fff”, textAlign: “left”, fontWeight: 600, fontSize: 11, whiteSpace: “nowrap” }}>{h}</th>
))}
</tr>
</thead>
<tbody>
{items.map((item, i) => (
<tr key={i} style={{ background: i % 2 === 0 ? “#f8fafc” : “#fff”, borderBottom: “1px solid #eee” }}>
<td style={{ padding: “7px 10px”, fontWeight: 600, color: “#334155”, minWidth: 100 }}>{item.component}</td>
<td style={{ padding: “7px 10px”, maxWidth: 220 }}>{item.threat}</td>
<td style={{ padding: “7px 10px”, whiteSpace: “nowrap” }}><Badge risk={item.risk} /></td>
<td style={{ padding: “7px 10px”, maxWidth: 260, color: “#334155” }}>{item.mitigation}</td>
<td style={{ padding: “7px 10px”, color: “#64748b”, fontFamily: “monospace”, fontSize: 11 }}>{item.cwe}</td>
<td style={{ padding: “7px 10px”, color: “#2E74B5”, fontSize: 11 }}>{item.reference}</td>
</tr>
))}
</tbody>
</table>
</div>
</div>
);
}

export default function App() {
const [phase, setPhase]       = useState(“upload”);
const [dragOver, setDragOver] = useState(false);
const [imgPreview, setPreview]= useState(null);
const [imgB64, setB64]        = useState(null);
const [result, setResult]     = useState(null);
const [error, setError]       = useState(””);
const [tab, setTab]           = useState(“Overview”);
const fileRef = useRef();

const loadFile = useCallback((file) => {
if (!file?.type.startsWith(“image/”)) return;
const r = new FileReader();
r.onload = e => { setPreview(e.target.result); setB64(e.target.result); };
r.readAsDataURL(file);
}, []);

const run = async () => {
if (!imgB64) return;
setPhase(“loading”);
try {
const res = await fetch(`${API}/analyze`, {
method: “POST”,
headers: { “Content-Type”: “application/json” },
body: JSON.stringify({ image: imgB64 }),
});
const data = await res.json();
if (!res.ok || !data.success) throw new Error(data.error || “Analysis failed”);
setResult(data);
setPhase(“result”);
setTab(“Overview”);
} catch (e) {
setError(e.message);
setPhase(“error”);
}
};

const download = () => {
if (!result?.docx_b64) return;
const blob = new Blob(
[Uint8Array.from(atob(result.docx_b64), c => c.charCodeAt(0))],
{ type: “application/vnd.openxmlformats-officedocument.wordprocessingml.document” }
);
const a = Object.assign(document.createElement(“a”), {
href: URL.createObjectURL(blob), download: result.docx_filename || “threat_report.docx”
});
a.click(); URL.revokeObjectURL(a.href);
};

const reset = () => { setPhase(“upload”); setPreview(null); setB64(null); setResult(null); setError(””); };

const rc = result ? (RISK_STYLE[result.overall_risk] || RISK_STYLE.medium) : null;

return (
<div style={{ minHeight: “100vh”, background: “#0f172a”, fontFamily: “‘Segoe UI’, system-ui, sans-serif”, color: “#e2e8f0” }}>
<div style={{ padding: “20px 32px”, borderBottom: “1px solid rgba(255,255,255,0.06)”, display: “flex”, alignItems: “center”, gap: 12 }}>
<div style={{ width: 38, height: 38, borderRadius: 9, background: “linear-gradient(135deg,#2E74B5,#1F3864)”, display: “flex”, alignItems: “center”, justifyContent: “center”, fontSize: 18 }}>🛡️</div>
<div>
<div style={{ fontWeight: 800, fontSize: 17, letterSpacing: -0.3 }}>Arch Threat Modeler</div>
<div style={{ fontSize: 11, color: “#64748b” }}>100% offline · STRIDE · Rule-based · No AI API</div>
</div>
</div>

```
  <div style={{ maxWidth: 1080, margin: "0 auto", padding: "28px 20px" }}>

    {(phase === "upload" || phase === "error") && (
      <div>
        <div style={{ textAlign: "center", marginBottom: 28 }}>
          <h1 style={{ fontSize: 28, fontWeight: 800, margin: 0, background: "linear-gradient(90deg,#60a5fa,#a78bfa)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
            Architecture Threat Modeling
          </h1>
          <p style={{ color: "#64748b", marginTop: 6, fontSize: 14 }}>
            Upload your diagram — anonymization & STRIDE analysis run entirely offline.
          </p>
        </div>

        <div
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => { e.preventDefault(); setDragOver(false); loadFile(e.dataTransfer.files[0]); }}
          onClick={() => fileRef.current?.click()}
          style={{
            border: `2px dashed ${dragOver ? "#60a5fa" : "rgba(96,165,250,0.25)"}`,
            borderRadius: 14, padding: "44px 28px", textAlign: "center", cursor: "pointer",
            background: dragOver ? "rgba(96,165,250,0.06)" : "rgba(255,255,255,0.02)",
            transition: "all .2s", marginBottom: 20
          }}
        >
          <input ref={fileRef} type="file" accept="image/*" style={{ display: "none" }}
            onChange={e => loadFile(e.target.files[0])} />
          {imgPreview
            ? <div><img src={imgPreview} alt="preview" style={{ maxHeight: 260, maxWidth: "100%", borderRadius: 8, boxShadow: "0 6px 24px rgba(0,0,0,0.5)", marginBottom: 12 }} />
                <div style={{ color: "#60a5fa", fontSize: 12 }}>Click to change image</div></div>
            : <div>
                <div style={{ fontSize: 44, marginBottom: 10 }}>📐</div>
                <div style={{ fontWeight: 600, fontSize: 15 }}>Drop architecture diagram here</div>
                <div style={{ color: "#64748b", fontSize: 12, marginTop: 4 }}>PNG · JPG · BMP — network maps, infra diagrams, renders</div>
              </div>}
        </div>

        {phase === "error" && (
          <div style={{ background: "#3a1010", border: "1px solid #C00000", borderRadius: 8, padding: "12px 16px", marginBottom: 16, color: "#ffaaaa", fontSize: 13 }}>
            ❌ {error}
          </div>
        )}

        <div style={{ background: "rgba(96,165,250,0.07)", border: "1px solid rgba(96,165,250,0.2)", borderRadius: 10, padding: "12px 16px", marginBottom: 20, fontSize: 12, color: "#94a3b8" }}>
          🔒 <strong style={{ color: "#60a5fa" }}>Fully offline:</strong> IPs, hostnames, URLs, emails, and tokens are detected by regex + OCR and redacted <em>before</em> any further processing. STRIDE threats are generated by a built-in rule engine — <strong>zero data leaves your machine.</strong>
        </div>

        <button onClick={run} disabled={!imgB64} style={{
          width: "100%", padding: "14px", borderRadius: 10, border: "none",
          cursor: imgB64 ? "pointer" : "not-allowed",
          background: imgB64 ? "linear-gradient(135deg,#2E74B5,#1F3864)" : "#1e293b",
          color: imgB64 ? "#fff" : "#475569", fontWeight: 700, fontSize: 15,
          boxShadow: imgB64 ? "0 4px 18px rgba(46,116,181,0.4)" : "none", transition: "all .2s"
        }}>🔍 Analyze Architecture</button>
      </div>
    )}

    {phase === "loading" && (
      <div style={{ textAlign: "center", padding: "72px 0" }}>
        <div style={{ fontSize: 48, marginBottom: 16, animation: "spin 1.6s linear infinite" }}>⚙️</div>
        <div style={{ fontWeight: 700, fontSize: 18 }}>Running offline analysis…</div>
        <div style={{ color: "#64748b", fontSize: 13, marginTop: 6 }}>OCR → Anonymize → Classify → STRIDE rules → Report</div>
        <style>{`@keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}`}</style>
      </div>
    )}

    {phase === "result" && result && (
      <div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20, flexWrap: "wrap", gap: 10 }}>
          <div>
            <div style={{ fontWeight: 800, fontSize: 20 }}>Analysis Complete</div>
            <div style={{ color: "#64748b", fontSize: 12 }}>{result.threat_count} threats · {result.components.length} components detected</div>
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button onClick={reset} style={{ padding: "9px 16px", borderRadius: 7, border: "1px solid rgba(255,255,255,0.12)", background: "transparent", color: "#94a3b8", cursor: "pointer", fontSize: 12 }}>↩ New</button>
            <button onClick={download} style={{ padding: "9px 18px", borderRadius: 7, border: "none", background: "linear-gradient(135deg,#2E74B5,#1F3864)", color: "#fff", cursor: "pointer", fontWeight: 700, fontSize: 12, boxShadow: "0 2px 10px rgba(46,116,181,0.5)" }}>📥 Download Word Report</button>
          </div>
        </div>

        <div style={{ background: rc.bg, border: `2px solid ${rc.border}`, borderRadius: 10, padding: "14px 20px", marginBottom: 20, display: "flex", alignItems: "center", gap: 14 }}>
          <span style={{ fontSize: 30 }}>⚠️</span>
          <div>
            <div style={{ fontWeight: 700, color: rc.text, fontSize: 15 }}>Overall Risk: {result.overall_risk.toUpperCase()}</div>
            <div style={{ color: "#555", fontSize: 12 }}>{result.threat_count} threats across {result.components.length} detected components</div>
          </div>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
          {[["🔴 Original", imgPreview, "#3a1010", "#ff444433"],
            ["🟢 Anonymized", result.anonymized_image, "#0f2a1a", "#44ff8833"]].map(([label, src, bg, brd]) => (
            <div key={label} style={{ background: bg, border: `1px solid ${brd}`, borderRadius: 10, padding: 12, textAlign: "center" }}>
              <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 8, color: label.startsWith("🔴") ? "#ffaaaa" : "#aaffcc" }}>{label}</div>
              <img src={src} alt={label} style={{ maxWidth: "100%", maxHeight: 180, borderRadius: 6, objectFit: "contain" }} />
            </div>
          ))}
        </div>

        <div style={{ display: "flex", gap: 3, marginBottom: 16, background: "rgba(255,255,255,0.04)", padding: 3, borderRadius: 8 }}>
          {TABS.map(t => (
            <button key={t} onClick={() => setTab(t)} style={{
              padding: "7px 14px", borderRadius: 6, border: "none", cursor: "pointer", fontSize: 12, fontWeight: 600,
              background: tab === t ? "rgba(46,116,181,0.85)" : "transparent",
              color: tab === t ? "#fff" : "#64748b", transition: "all .15s"
            }}>{t}</button>
          ))}
        </div>

        <div style={{ background: "rgba(255,255,255,0.03)", borderRadius: 12, padding: 20, border: "1px solid rgba(255,255,255,0.07)" }}>
          {tab === "Overview" && (
            <div>
              <div style={{ fontWeight: 700, color: "#60a5fa", marginBottom: 14 }}>Detected Components</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px,1fr))", gap: 10 }}>
                {result.components.map((c, i) => (
                  <div key={i} style={{ background: "rgba(255,255,255,0.05)", borderRadius: 8, padding: "12px 14px", border: "1px solid rgba(255,255,255,0.07)" }}>
                    <div style={{ fontWeight: 700, fontSize: 13 }}>{c.name}</div>
                    <div style={{ color: "#60a5fa", fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5, margin: "3px 0" }}>{c.category}</div>
                    <div style={{ color: "#64748b", fontSize: 11 }}>{c.description}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {tab === "STRIDE" && (
            <div>
              {STRIDE_META.map(meta => (
                <ThreatTable key={meta.key} meta={meta} items={result.stride[meta.key]} />
              ))}
            </div>
          )}

          {tab === "Recommendations" && (
            <div>
              <div style={{ fontWeight: 700, color: "#60a5fa", marginBottom: 14 }}>Top Recommendations (by risk)</div>
              {result.recommendations.map((r, i) => {
                const risk = r.match(/^\[(\w+)\]/)?.[1]?.toLowerCase() || "low";
                const s = RISK_STYLE[risk] || RISK_STYLE.low;
                return (
                  <div key={i} style={{ display: "flex", gap: 12, padding: "12px 14px", background: "rgba(255,255,255,0.04)", borderRadius: 8, marginBottom: 8, border: "1px solid rgba(255,255,255,0.06)" }}>
                    <div style={{ width: 26, height: 26, borderRadius: 6, background: s.bg, border: `1px solid ${s.border}`, display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 800, fontSize: 12, color: s.text, flexShrink: 0 }}>{i+1}</div>
                    <div style={{ fontSize: 13, lineHeight: 1.5, paddingTop: 2 }}>{r.replace(/^\[\w+\]\s*/, "")}</div>
                  </div>
                );
              })}
            </div>
          )}

          {tab === "Anon Map" && (
            <div>
              <div style={{ fontWeight: 700, color: "#60a5fa", marginBottom: 6 }}>Anonymization Map</div>
              <div style={{ color: "#64748b", fontSize: 12, marginBottom: 14 }}>⚠️ Confidential — included in the Word report.</div>
              {Object.keys(result.mapping).length === 0
                ? <div style={{ color: "#64748b", fontSize: 13 }}>No sensitive data detected in the image.</div>
                : <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
                    <thead>
                      <tr style={{ background: "#1F3864" }}>
                        <th style={{ padding: "8px 12px", color: "#fff", textAlign: "left" }}>Label in Report</th>
                        <th style={{ padding: "8px 12px", color: "#fff", textAlign: "left" }}>Original Value</th>
                      </tr>
                    </thead>
                    <tbody>
                      {Object.entries(result.mapping).map(([orig, anon], i) => (
                        <tr key={i} style={{ background: i%2===0?"rgba(255,255,255,0.03)":"transparent", borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
                          <td style={{ padding: "7px 12px", fontFamily: "monospace", color: "#60a5fa" }}>{anon}</td>
                          <td style={{ padding: "7px 12px", fontFamily: "monospace", color: "#fca5a5" }}>{orig}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
              }
            </div>
          )}
        </div>
      </div>
    )}
  </div>
</div>
```

);
}
