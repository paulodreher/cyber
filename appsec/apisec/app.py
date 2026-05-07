"""
OWASP API Security Top 10 — Interactive Learning App
Run with: streamlit run app.py
"""

from __future__ import annotations
import io
import streamlit as st

# ── Page config (must be first Streamlit call) ──────────────────────────────
st.set_page_config(
    page_title="OWASP API Security Top 10",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Local imports ────────────────────────────────────────────────────────────
from data.vulnerabilities import VULNERABILITIES  # noqa: E402
from components.vuln_detail import render_vuln_detail  # noqa: E402
from components.qa_panel import render_qa_panel  # noqa: E402
from components.summary import render_summary, mark_visited  # noqa: E402

# ── Global CSS ───────────────────────────────────────────────────────────────
st.markdown(
    """
    <style>
    /* ── Base ── */
    html, body, [class*="css"] {
        font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
    }

    .stApp {
        background: #0d1117;
        color: #c9d1d9;
    }

    /* ── Sidebar ── */
    [data-testid="stSidebar"] {
        background: #0f1923 !important;
        border-right: 1px solid #1f2937;
    }

    [data-testid="stSidebar"] .stMarkdown p,
    [data-testid="stSidebar"] .stMarkdown span {
        color: #8b949e !important;
    }

    /* ── Buttons ── */
    .stButton > button {
        background: #1a2535;
        color: #c9d1d9;
        border: 1px solid #2d3748;
        border-radius: 8px;
        font-size: 0.82rem;
        padding: 6px 10px;
        transition: all 0.2s;
    }
    .stButton > button:hover {
        background: #1e3a5f;
        border-color: #3498db;
        color: #e6edf3;
        box-shadow: 0 0 8px #3498db44;
    }

    /* ── Tabs ── */
    .stTabs [data-baseweb="tab-list"] {
        background: #0f1923;
        border-bottom: 1px solid #1f2937;
        gap: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        background: transparent;
        color: #8b949e;
        border-radius: 8px 8px 0 0;
        padding: 8px 16px;
        font-size: 0.9rem;
    }
    .stTabs [aria-selected="true"] {
        background: #1a2535 !important;
        color: #e6edf3 !important;
        border-top: 2px solid #3498db !important;
    }

    /* ── Code blocks ── */
    .stCode, [data-testid="stCodeBlock"] {
        border: 1px solid #2d3748;
        border-radius: 8px;
    }

    /* ── Metrics ── */
    [data-testid="stMetric"] {
        background: #1a2535;
        border: 1px solid #2d3748;
        border-radius: 10px;
        padding: 12px 16px;
    }
    [data-testid="stMetricValue"] {
        color: #e6edf3 !important;
    }
    [data-testid="stMetricLabel"] {
        color: #8b949e !important;
    }

    /* ── Expander ── */
    .streamlit-expanderHeader {
        background: #1a2535 !important;
        color: #c9d1d9 !important;
        border-radius: 8px;
    }

    /* ── Selectbox / inputs ── */
    .stSelectbox [data-baseweb="select"] {
        background: #1a2535;
        border-color: #2d3748;
    }

    .stTextInput input {
        background: #1a2535 !important;
        color: #e6edf3 !important;
        border: 1px solid #2d3748 !important;
        border-radius: 8px !important;
    }
    .stTextInput input:focus {
        border-color: #3498db !important;
        box-shadow: 0 0 0 2px #3498db33 !important;
    }

    /* ── Info / warning boxes ── */
    .stAlert {
        background: #1a2535;
        border: 1px solid #3498db44;
        color: #c9d1d9;
        border-radius: 8px;
    }

    /* ── Divider ── */
    hr {
        border-color: #1f2937 !important;
    }

    /* ── Sidebar radio / selectbox ── */
    [data-testid="stSidebar"] .stRadio label,
    [data-testid="stSidebar"] .stSelectbox label {
        color: #8b949e !important;
    }

    /* ── Form submit button ── */
    .stFormSubmitButton > button {
        background: #3498db !important;
        color: #fff !important;
        border: none !important;
        border-radius: 8px !important;
        font-weight: 600 !important;
        padding: 8px 16px !important;
    }
    .stFormSubmitButton > button:hover {
        background: #2980b9 !important;
        box-shadow: 0 0 12px #3498db66 !important;
    }

    /* ── Scrollbar ── */
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: #0d1117; }
    ::-webkit-scrollbar-thumb { background: #2d3748; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: #3498db; }
    </style>
    """,
    unsafe_allow_html=True,
)


# ── PDF generation ─────────────────────────────────────────────────────────────
def _generate_pdf() -> bytes:
    """Generate a PDF summary report of all OWASP API vulnerabilities."""
    try:
        from fpdf import FPDF
    except ImportError:
        return _fallback_text_report()

    class PDF(FPDF):
        def header(self):
            self.set_fill_color(13, 17, 23)
            self.rect(0, 0, 210, 297, "F")
            self.set_font("Helvetica", "B", 16)
            self.set_text_color(231, 76, 60)
            self.cell(0, 12, "OWASP API Security Top 10 — 2023", ln=True, align="C")
            self.set_font("Helvetica", "", 9)
            self.set_text_color(139, 148, 158)
            self.cell(0, 6, "Security Report — Generated for Developer Education", ln=True, align="C")
            self.ln(4)
            self.set_draw_color(231, 76, 60)
            self.set_line_width(0.5)
            self.line(10, self.get_y(), 200, self.get_y())
            self.ln(4)

        def footer(self):
            self.set_y(-15)
            self.set_font("Helvetica", "I", 8)
            self.set_text_color(74, 85, 104)
            self.cell(0, 10, f"Page {self.page_no()} — OWASP API Security Top 10 | owasp.org/API-Security", align="C")

    RISK_COLORS_RGB = {
        "Critical": (231, 76, 60),
        "High":     (230, 126, 34),
        "Medium":   (241, 196, 15),
        "Low":      (46, 204, 113),
    }

    pdf = PDF()
    pdf.set_auto_page_break(auto=True, margin=20)

    # Cover page
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(231, 76, 60)
    pdf.ln(20)
    pdf.cell(0, 14, "OWASP API Security", ln=True, align="C")
    pdf.cell(0, 14, "Top 10 — 2023", ln=True, align="C")
    pdf.ln(8)
    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(201, 209, 217)
    pdf.cell(0, 8, "Developer Security Education Report", ln=True, align="C")
    pdf.ln(6)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(139, 148, 158)
    pdf.cell(0, 6, "Based on OWASP API Security Project | https://owasp.org/API-Security/", ln=True, align="C")

    pdf.ln(16)
    pdf.set_draw_color(52, 152, 219)
    pdf.set_line_width(0.3)
    pdf.line(30, pdf.get_y(), 180, pdf.get_y())
    pdf.ln(10)

    # Summary table on cover
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(201, 209, 217)
    pdf.cell(0, 8, "Vulnerability Summary", ln=True, align="C")
    pdf.ln(4)

    for vuln in VULNERABILITIES:
        risk = vuln.get("risk_rating", "Medium")
        rgb = RISK_COLORS_RGB.get(risk, (201, 209, 217))
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*rgb)
        vid = vuln["id"]
        title_parts = vuln["title"].split("–", 1)
        short = title_parts[1].strip() if len(title_parts) > 1 else vuln["title"]
        pdf.cell(18, 6, vid, border=0)
        pdf.set_text_color(201, 209, 217)
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(130, 6, short[:70], border=0)
        pdf.set_text_color(*rgb)
        pdf.cell(0, 6, risk, ln=True, align="R")

    # Vulnerability detail pages
    for vuln in VULNERABILITIES:
        pdf.add_page()
        risk = vuln.get("risk_rating", "Medium")
        rgb = RISK_COLORS_RGB.get(risk, (201, 209, 217))

        # Title
        pdf.set_font("Helvetica", "B", 14)
        pdf.set_text_color(*rgb)
        title = vuln["title"]
        pdf.multi_cell(0, 8, title, align="L")
        pdf.ln(2)

        # Risk badge
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(*rgb)
        pdf.cell(0, 6, f"Risk Level: {risk}", ln=True)
        pdf.ln(2)

        # Description
        pdf.set_font("Helvetica", "", 10)
        pdf.set_text_color(201, 209, 217)
        desc = vuln.get("short_desc", "")
        pdf.multi_cell(0, 6, _clean_text(desc))
        pdf.ln(4)

        # Section: What NOT to do
        _pdf_section_header(pdf, "What NOT to do (Vulnerable Pattern)", (231, 76, 60))
        for lang, code in list(vuln.get("vulnerable_code", {}).items())[:2]:
            pdf.set_font("Helvetica", "BI", 9)
            pdf.set_text_color(139, 148, 158)
            pdf.cell(0, 5, lang, ln=True)
            pdf.set_font("Courier", "", 7.5)
            pdf.set_text_color(230, 237, 243)
            pdf.set_fill_color(22, 27, 34)
            code_lines = code.strip().split("\n")[:20]
            for line in code_lines:
                safe_line = _clean_text(line[:100])
                pdf.cell(0, 4.5, safe_line, ln=True, fill=True)
            pdf.ln(3)

        # Section: Secure code
        _pdf_section_header(pdf, "Secure Implementation", (46, 204, 113))
        for lang, code in list(vuln.get("secure_code", {}).items())[:1]:
            pdf.set_font("Helvetica", "BI", 9)
            pdf.set_text_color(139, 148, 158)
            pdf.cell(0, 5, lang, ln=True)
            pdf.set_font("Courier", "", 7.5)
            pdf.set_text_color(230, 237, 243)
            pdf.set_fill_color(22, 27, 34)
            code_lines = code.strip().split("\n")[:20]
            for line in code_lines:
                safe_line = _clean_text(line[:100])
                pdf.cell(0, 4.5, safe_line, ln=True, fill=True)
            pdf.ln(3)

        # Section: Attack
        _pdf_section_header(pdf, "Attack (curl)", (155, 89, 182))
        attacks = vuln.get("curl_attacks", [])
        for attack in attacks[:2]:
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(201, 209, 217)
            pdf.multi_cell(0, 5, _clean_text(attack["title"]))
            pdf.set_font("Courier", "", 7.5)
            pdf.set_text_color(230, 237, 243)
            pdf.set_fill_color(22, 27, 34)
            cmd_lines = attack["command"].split("\n")[:12]
            for line in cmd_lines:
                pdf.cell(0, 4.5, _clean_text(line[:100]), ln=True, fill=True)
            pdf.ln(2)
            pdf.set_font("Helvetica", "I", 8)
            pdf.set_text_color(243, 156, 18)
            pdf.multi_cell(0, 5, _clean_text(attack["explanation"]))
            pdf.ln(3)

        # Section: References
        _pdf_section_header(pdf, "References", (52, 152, 219))
        for ref in vuln.get("references", [])[:4]:
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(52, 152, 219)
            pdf.multi_cell(0, 5, f"• {ref['title']}: {ref['url']}")

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def _pdf_section_header(pdf, title: str, rgb: tuple) -> None:
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(*rgb)
    pdf.ln(2)
    pdf.cell(0, 7, title, ln=True)
    pdf.set_draw_color(*rgb)
    pdf.set_line_width(0.2)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(2)


def _clean_text(text: str) -> str:
    """Remove non-latin1 characters for fpdf compatibility."""
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _fallback_text_report() -> bytes:
    """Return a minimal plain-text report if fpdf is unavailable."""
    lines = ["OWASP API Security Top 10 - 2023 Report\n", "=" * 50 + "\n\n"]
    for vuln in VULNERABILITIES:
        lines.append(f"{vuln['id']}: {vuln['title']}\n")
        lines.append(f"Risk: {vuln.get('risk_rating', 'N/A')}\n")
        lines.append(f"{vuln.get('short_desc', '')}\n\n")
    return "".join(lines).encode("utf-8")


# ── Session state init ────────────────────────────────────────────────────────
if "visited" not in st.session_state:
    st.session_state.visited = set()
if "current_page" not in st.session_state:
    st.session_state.current_page = "summary"


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    # Logo / title block
    st.markdown(
        """
        <div style="
            background: linear-gradient(135deg, #0f1923 0%, #1a2535 100%);
            border: 1px solid #e74c3c44;
            border-radius: 12px;
            padding: 20px 16px;
            margin-bottom: 20px;
            text-align: center;
        ">
            <div style="font-size: 2.5rem; margin-bottom: 8px;">🔐</div>
            <div style="
                color: #e74c3c;
                font-size: 1.1rem;
                font-weight: 700;
                font-family: 'Courier New', monospace;
                letter-spacing: 1px;
            ">OWASP API Security</div>
            <div style="color: #8b949e; font-size: 0.8rem; margin-top: 4px;">
                Top 10 — 2023 Edition
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Navigation header
    st.markdown(
        "<p style='color:#8b949e; font-size:0.78rem; text-transform:uppercase; "
        "letter-spacing:2px; margin-bottom:8px;'>Navigation</p>",
        unsafe_allow_html=True,
    )

    # Summary button
    visited_count = len(st.session_state.visited)
    total_count = len(VULNERABILITIES)

    if st.button(
        f"📊 Dashboard  ({visited_count}/{total_count} studied)",
        key="nav_summary",
        use_container_width=True,
    ):
        st.session_state.current_page = "summary"
        st.rerun()

    if st.button(
        "💬 Q&A Assistant",
        key="nav_qa",
        use_container_width=True,
    ):
        st.session_state.current_page = "qa"
        st.rerun()

    st.markdown(
        "<p style='color:#8b949e; font-size:0.78rem; text-transform:uppercase; "
        "letter-spacing:2px; margin-top:16px; margin-bottom:8px;'>Vulnerabilities</p>",
        unsafe_allow_html=True,
    )

    # Vulnerability navigation buttons
    for vuln in VULNERABILITIES:
        vid = vuln["id"]
        risk = vuln.get("risk_rating", "Medium")
        risk_colors = {
            "Critical": "#e74c3c",
            "High": "#e67e22",
            "Medium": "#f1c40f",
            "Low": "#2ecc71",
        }
        c = risk_colors.get(risk, "#ccc")
        is_visited = vid in st.session_state.visited
        check = "✅ " if is_visited else ""

        # Short label: "API1 — BOLA"
        title_short = vuln["title"].split("–", 1)
        short_name = title_short[1].strip().split("(")[0].strip() if len(title_short) > 1 else vid

        label = f"{check}{vid} — {short_name}"

        _ = st.button(
            label,
            key=f"nav_{vid}",
            use_container_width=True,
            help=vuln["short_desc"][:120] + "...",
        )
        if _:
            st.session_state.current_page = f"vuln_{vid}"
            mark_visited(vid)
            st.rerun()

    # ── PDF Export ─────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown(
        "<p style='color:#8b949e; font-size:0.78rem; text-transform:uppercase; "
        "letter-spacing:2px; margin-bottom:8px;'>Export</p>",
        unsafe_allow_html=True,
    )

    if st.button("📄 Generate PDF Report", key="gen_pdf", use_container_width=True):
        pdf_bytes = _generate_pdf()
        st.download_button(
            label="⬇️ Download PDF",
            data=pdf_bytes,
            file_name="owasp_api_security_report.pdf",
            mime="application/pdf",
            key="dl_pdf",
            use_container_width=True,
        )

    # ── Footer ──────────────────────────────────────────────────────────────
    st.markdown("<br>" * 2, unsafe_allow_html=True)
    st.markdown(
        """
        <div style="
            text-align: center;
            color: #4a5568;
            font-size: 0.75rem;
            border-top: 1px solid #1f2937;
            padding-top: 12px;
        ">
            Based on <a href="https://owasp.org/API-Security/" target="_blank"
                style="color:#3498db; text-decoration:none;">OWASP API Security 2023</a><br>
            For educational purposes only.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ── Main content area ─────────────────────────────────────────────────────────
page = st.session_state.current_page

if page == "summary":
    render_summary()

elif page == "qa":
    render_qa_panel()

elif page.startswith("vuln_"):
    vid = page.replace("vuln_", "")
    vuln = next((v for v in VULNERABILITIES if v["id"] == vid), None)
    if vuln:
        render_vuln_detail(vuln)
    else:
        st.error(f"Vulnerability '{vid}' not found.")

else:
    render_summary()
