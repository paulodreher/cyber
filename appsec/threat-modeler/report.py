“””
Generates a professional .docx threat modeling report.
Uses Node.js docx library — no AI involved.
“””

import json, subprocess, tempfile, os

RISK_HEX = {
“critical”: “C00000”,
“high”:     “E74C3C”,
“medium”:   “ED7D31”,
“low”:      “70AD47”,
}

STRIDE_ORDER = [
(“Spoofing”,               “S”, “🎭”),
(“Tampering”,              “T”, “🔧”),
(“Repudiation”,            “R”, “📋”),
(“Information Disclosure”, “I”, “🔓”),
(“Denial of Service”,      “D”, “🚫”),
(“Elevation of Privilege”, “E”, “⬆”),
]

def generate_docx(result: dict, output_path: str):
# Strip non-serializable fields before passing to JS
clean = {k: v for k, v in result.items() if k != “anonymized_image_bytes”}
script = _build_script(clean, output_path)
tmp = tempfile.NamedTemporaryFile(suffix=”.js”, delete=False, mode=“w”)
tmp.write(script)
tmp.close()
try:
r = subprocess.run([“node”, tmp.name], capture_output=True, text=True, timeout=60)
if r.returncode != 0:
raise RuntimeError(f”Node error: {r.stderr[:500]}”)
finally:
os.unlink(tmp.name)

def _build_script(result: dict, output_path: str) -> str:
data_json   = json.dumps(result,               ensure_ascii=False)
stride_json = json.dumps(STRIDE_ORDER,          ensure_ascii=False)
risk_json   = json.dumps(RISK_HEX,             ensure_ascii=False)
today       = **import**(“datetime”).date.today().strftime(”%d/%m/%Y”)

```
return f"""
```

‘use strict’;
const {{ Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
LevelFormat, PageBreak }} = require(‘docx’);
const fs = require(‘fs’);

const result      = {data_json};
const strideOrder = {stride_json};
const riskHex     = {risk_json};
const today       = “{today}”;

// ── helpers ──────────────────────────────────────────────────────────────────
const b = (style, size, color, text, italic) =>
new TextRun({{ text: String(text ?? ‘’), bold: style === ‘bold’, italics: !!italic,
size, color: color || ‘000000’, font: ‘Calibri’ }});

const border1 = {{ style: BorderStyle.SINGLE, size: 1, color: ‘CCCCCC’ }};
const borders = {{ top: border1, bottom: border1, left: border1, right: border1 }};
const cm      = {{ top: 80, bottom: 80, left: 120, right: 120 }};

function hCell(text, w, bgHex) {{
return new TableCell({{ borders, margins: cm,
width: {{ size: w, type: WidthType.DXA }},
shading: {{ fill: bgHex || ‘1F3864’, type: ShadingType.CLEAR }},
children: [new Paragraph({{ children: [b(‘bold’, 18, ‘FFFFFF’, text)] }})] }});
}}
function dCell(text, w, color) {{
return new TableCell({{ borders, margins: cm,
width: {{ size: w, type: WidthType.DXA }},
children: [new Paragraph({{ children: [b(’’, 18, color || ‘222222’, text)] }})] }});
}}
const riskBg = {{ critical:‘FFE0E0’, high:‘FFE8E8’, medium:‘FFF3E0’, low:‘E8F5E9’ }};
function rCell(risk, w) {{
const hex = riskHex[risk] || ‘595959’;
const bg  = riskBg[risk]  || ‘FFFFFF’;
return new TableCell({{ borders, margins: cm,
width: {{ size: w, type: WidthType.DXA }},
shading: {{ fill: bg, type: ShadingType.CLEAR }},
children: [new Paragraph({{ children: [b(‘bold’, 17, hex, risk.toUpperCase())] }})] }});
}}
function h1(text) {{
return new Paragraph({{ heading: HeadingLevel.HEADING_1,
spacing: {{ before: 320, after: 120 }},
children: [b(‘bold’, 28, ‘1F3864’, text)] }});
}}
function h2(text) {{
return new Paragraph({{ heading: HeadingLevel.HEADING_2,
spacing: {{ before: 220, after: 80 }},
children: [b(‘bold’, 22, ‘2E74B5’, text)] }});
}}
function body(text) {{
return new Paragraph({{ spacing: {{ after: 100 }},
children: [b(’’, 20, ‘333333’, text)] }});
}}
function bullet(text) {{
return new Paragraph({{ numbering: {{ reference: ‘bullets’, level: 0 }},
spacing: {{ after: 80 }},
children: [b(’’, 20, ‘333333’, text)] }});
}}
function spacer() {{
return new Paragraph({{ spacing: {{ after: 120 }}, children: [new TextRun(’’)] }});
}}
function divider(color) {{
return new Paragraph({{
border: {{ bottom: {{ style: BorderStyle.SINGLE, size: 4, color: color || ‘CCCCCC’, space: 1 }} }},
spacing: {{ after: 160 }}, children: [new TextRun(’’)] }});
}}

// ── Components table ──────────────────────────────────────────────────────────
const compRows = [
new TableRow({{ children: [hCell(‘Component’, 2800), hCell(‘Type’, 2000), hCell(‘Description’, 4560)] }}),
…(result.components || []).map(c => new TableRow({{ children: [
dCell(c.name, 2800), dCell(c.category, 2000), dCell(c.description, 4560)
]}})
)];

// ── STRIDE tables ─────────────────────────────────────────────────────────────
const strideBlocks = [];
for (const [cat, letter, icon] of strideOrder) {{
const items = result.stride[cat] || [];
strideBlocks.push(h2(icon + ’  ’ + cat + ’ (’ + letter + ‘)’));
if (items.length === 0) {{
strideBlocks.push(body(‘No threats identified in this category.’));
strideBlocks.push(spacer());
continue;
}}
const rows = [
new TableRow({{ children: [
hCell(‘Component’, 1800), hCell(‘Threat’, 3000), hCell(‘Risk’, 800),
hCell(‘Mitigation’, 2560), hCell(‘CWE’, 700), hCell(‘Reference’, 900)
]}})
];
for (const item of items) {{
rows.push(new TableRow({{ children: [
dCell(item.component, 1800),
dCell(item.threat, 3000),
rCell(item.risk, 800),
dCell(item.mitigation, 2560),
dCell(item.cwe, 700, ‘555555’),
dCell(item.reference, 900, ‘2E74B5’),
]}}));
}}
strideBlocks.push(new Table({{
width: {{ size: 9760, type: WidthType.DXA }},
columnWidths: [1800, 3000, 800, 2560, 700, 900],
rows
}}));
strideBlocks.push(spacer());
}}

// ── Recommendations ───────────────────────────────────────────────────────────
const recBlocks = (result.recommendations || []).map(r => bullet(r));

// ── Mapping table ─────────────────────────────────────────────────────────────
const mapEntries = Object.entries(result.mapping || {{}});
const mapRows = [
new TableRow({{ children: [hCell(‘Anonymized Label’, 4680), hCell(‘Original Value (CONFIDENTIAL)’, 4680)] }}),
…mapEntries.map(([orig, anon]) => new TableRow({{ children: [
dCell(anon, 4680, ‘2E74B5’), dCell(orig, 4680, ‘C00000’)
]}})
)];

// ── Overall risk banner ───────────────────────────────────────────────────────
const overallRisk = result.overall_risk || ‘medium’;
const rc = riskHex[overallRisk] || ‘595959’;
const riskBanner = new Paragraph({{
alignment: AlignmentType.CENTER,
spacing: {{ before: 200, after: 200 }},
border: {{
top:    {{ style: BorderStyle.SINGLE, size: 8, color: rc, space: 1 }},
bottom: {{ style: BorderStyle.SINGLE, size: 8, color: rc, space: 1 }},
}},
children: [b(‘bold’, 32, rc, ’Overall Risk: ’ + overallRisk.toUpperCase())]
}});

// ── Document ──────────────────────────────────────────────────────────────────
const doc = new Document({{
numbering: {{ config: [{{
reference: ‘bullets’,
levels: [{{ level: 0, format: LevelFormat.BULLET, text: ‘\u2022’,
alignment: AlignmentType.LEFT,
style: {{ paragraph: {{ indent: {{ left: 720, hanging: 360 }} }} }} }}]
}}] }},
styles: {{
default: {{ document: {{ run: {{ font: ‘Calibri’, size: 20 }} }} }},
paragraphStyles: [
{{ id: ‘Heading1’, name: ‘Heading 1’, basedOn: ‘Normal’, next: ‘Normal’, quickFormat: true,
run: {{ size: 28, bold: true, font: ‘Calibri’, color: ‘1F3864’ }},
paragraph: {{ spacing: {{ before: 320, after: 120 }}, outlineLevel: 0 }} }},
{{ id: ‘Heading2’, name: ‘Heading 2’, basedOn: ‘Normal’, next: ‘Normal’, quickFormat: true,
run: {{ size: 22, bold: true, font: ‘Calibri’, color: ‘2E74B5’ }},
paragraph: {{ spacing: {{ before: 220, after: 80 }}, outlineLevel: 1 }} }},
]
}},
sections: [{{
properties: {{
page: {{
size: {{ width: 12240, height: 15840 }},
margin: {{ top: 1440, right: 1080, bottom: 1440, left: 1080 }}
}}
}},
children: [
// ── Cover ───────────────────────────────────────────────────────────
new Paragraph({{ spacing: {{ before: 1200, after: 200 }}, alignment: AlignmentType.CENTER,
children: [b(‘bold’, 52, ‘1F3864’, ‘THREAT MODELING REPORT’)] }}),
new Paragraph({{ spacing: {{ after: 120 }}, alignment: AlignmentType.CENTER,
children: [b(’’, 26, ‘2E74B5’, ‘STRIDE Framework  |  Offline Analysis’)] }}),
new Paragraph({{ spacing: {{ after: 80 }}, alignment: AlignmentType.CENTER,
children: [b(‘bold’, 20, ‘C00000’, ‘CONFIDENTIAL — For Internal Use Only’)] }}),
new Paragraph({{ spacing: {{ after: 600 }}, alignment: AlignmentType.CENTER,
children: [b(’’, 18, ‘888888’, ’Generated: ’ + today + ’   |   Threats found: ’ + result.threat_count)] }}),
divider(‘2E74B5’),

```
  // ── Risk Banner ──────────────────────────────────────────────────────
  riskBanner,
  spacer(),

  // ── 1. Components ────────────────────────────────────────────────────
  h1('1. Detected Architecture Components'),
  new Table({{
    width: {{ size: 9360, type: WidthType.DXA }},
    columnWidths: [2800, 2000, 4560], rows: compRows
  }}),
  spacer(),

  // ── 2. STRIDE Analysis ───────────────────────────────────────────────
  h1('2. STRIDE Threat Analysis'),
  ...strideBlocks,

  // ── 3. Recommendations ───────────────────────────────────────────────
  h1('3. Top Security Recommendations'),
  ...recBlocks,
  spacer(),

  // ── 4. Anonymization Mapping ─────────────────────────────────────────
  ...(mapEntries.length > 0 ? [
    h1('4. Anonymization Mapping'),
    body('The table below maps anonymized labels to the original values extracted from the diagram. Keep this section confidential.'),
    spacer(),
    new Table({{
      width: {{ size: 9360, type: WidthType.DXA }},
      columnWidths: [4680, 4680], rows: mapRows
    }}),
    spacer(),
  ] : []),

  // ── Footer note ──────────────────────────────────────────────────────
  divider(),
  new Paragraph({{ alignment: AlignmentType.CENTER, spacing: {{ before: 120 }},
    children: [b('', 16, 'AAAAAA',
      'Generated by Arch Threat Modeler — 100% offline, rule-based STRIDE engine. No data sent externally.',
      true)] }}),
]
```

}}]
}});

Packer.toBuffer(doc)
.then(buf => {{ fs.writeFileSync(”{output_path}”, buf); console.log(“OK”); }})
.catch(e => {{ console.error(e); process.exit(1); }});
“””
