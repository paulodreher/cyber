"""Summary / dashboard component showing visited topics and risk overview."""

from __future__ import annotations
import streamlit as st
from data.vulnerabilities import VULNERABILITIES


RISK_COLORS = {
    "Critical": "#e74c3c",
    "High":     "#e67e22",
    "Medium":   "#f1c40f",
    "Low":      "#2ecc71",
}

RISK_ICONS = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
}


def _init_session() -> None:
    if "visited" not in st.session_state:
        st.session_state.visited = set()


def mark_visited(vuln_id: str) -> None:
    """Call this when a vulnerability is opened."""
    _init_session()
    st.session_state.visited.add(vuln_id)


def render_summary() -> None:
    """Render the session progress summary and risk overview dashboard."""
    _init_session()
    visited = st.session_state.visited
    total = len(VULNERABILITIES)
    done = len(visited)
    pct = int((done / total) * 100) if total else 0

    # ── Header ──────────────────────────────────────────────────────────────
    st.markdown(
        """
        <div style="
            background: linear-gradient(135deg, #0f1923 0%, #1a2535 100%);
            border: 1px solid #9b59b644;
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 20px;
        ">
            <h2 style="color: #9b59b6; margin: 0; font-family: 'Courier New', monospace;">
                📊 Learning Progress & Risk Overview
            </h2>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Progress bar ─────────────────────────────────────────────────────────
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.metric("Topics Studied", f"{done} / {total}")
    with col_b:
        st.metric("Progress", f"{pct}%")
    with col_c:
        remaining = total - done
        st.metric("Remaining", remaining)

    # Progress bar
    st.markdown(
        f"""
        <div style="background:#1a2535; border-radius:8px; overflow:hidden;
                    height:12px; margin-bottom:24px; border:1px solid #9b59b633;">
            <div style="background: linear-gradient(90deg, #9b59b6, #3498db);
                        width:{pct}%; height:100%; border-radius:8px;
                        transition: width 0.5s;"></div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Risk Overview Table ──────────────────────────────────────────────────
    st.markdown("### 🎯 OWASP API Top 10 — Risk Overview")

    # Count risks by category
    risk_counts: dict[str, int] = {}
    for v in VULNERABILITIES:
        r = v.get("risk_rating", "Medium")
        risk_counts[r] = risk_counts.get(r, 0) + 1

    risk_col1, risk_col2, risk_col3, risk_col4 = st.columns(4)
    for col, (risk, count) in zip(
        [risk_col1, risk_col2, risk_col3, risk_col4],
        [("Critical", risk_counts.get("Critical", 0)),
         ("High",     risk_counts.get("High",     0)),
         ("Medium",   risk_counts.get("Medium",   0)),
         ("Low",      risk_counts.get("Low",      0))],
    ):
        with col:
            c = RISK_COLORS.get(risk, "#ccc")
            icon = RISK_ICONS.get(risk, "")
            st.markdown(
                f"""
                <div style="
                    background:#1a2535;
                    border:1px solid {c}55;
                    border-radius:10px;
                    padding:16px;
                    text-align:center;
                    box-shadow:0 0 12px {c}22;
                ">
                    <div style="font-size:2rem;">{icon}</div>
                    <div style="color:{c}; font-weight:700; font-size:1.8rem;">{count}</div>
                    <div style="color:#8b949e; font-size:0.85rem;">{risk}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Vulnerability checklist ───────────────────────────────────────────────
    st.markdown("### 📋 Vulnerability Checklist")

    for vuln in VULNERABILITIES:
        vid = vuln["id"]
        risk = vuln.get("risk_rating", "Medium")
        color = RISK_COLORS.get(risk, "#ccc")
        icon = RISK_ICONS.get(risk, "")
        is_visited = vid in visited
        check = "✅" if is_visited else "⬜"
        opacity = "1" if is_visited else "0.6"

        st.markdown(
            f"""
            <div style="
                background:#1a2535;
                border:1px solid {'#2ecc7144' if is_visited else '#ffffff11'};
                border-radius:8px;
                padding:12px 16px;
                margin-bottom:6px;
                opacity:{opacity};
                display:flex;
                align-items:center;
                gap:12px;
            ">
                <span style="font-size:1.2rem;">{check}</span>
                <span style="
                    background:{color};
                    color:#0f1923;
                    padding:2px 8px;
                    border-radius:12px;
                    font-size:0.75rem;
                    font-weight:700;
                    min-width:40px;
                    text-align:center;
                ">{vid}</span>
                <span style="color:#{'2ecc71' if is_visited else 'c9d1d9'}; font-size:0.95rem;">
                    {vuln['title'].split('–', 1)[1].strip() if '–' in vuln['title'] else vuln['title']}
                </span>
                <span style="margin-left:auto; font-size:0.85rem;">{icon} {risk}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # ── Key Takeaways ────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.markdown("### 💡 Key Security Principles")

    principles = [
        ("🔐", "Never trust the client", "Always validate authorization server-side, never rely on client-sent values."),
        ("📋", "Use allowlists", "Define exactly what is permitted — for inputs, fields, URLs, and HTTP methods."),
        ("⏱️", "Rate limit everything", "Especially auth endpoints, search, and sensitive business flows."),
        ("📝", "Maintain an API inventory", "Every endpoint must be documented, versioned, and monitored."),
        ("🔍", "Validate third-party data", "Treat all external API responses as untrusted input."),
        ("🔒", "Encrypt in transit and at rest", "TLS 1.2+, HSTS, bcrypt for passwords, AES-256 for sensitive data."),
    ]

    p_cols = st.columns(2)
    for i, (icon, title, desc) in enumerate(principles):
        with p_cols[i % 2]:
            st.markdown(
                f"""
                <div style="
                    background:#0f2318;
                    border:1px solid #2ecc7122;
                    border-radius:10px;
                    padding:16px;
                    margin-bottom:10px;
                ">
                    <div style="font-size:1.5rem; margin-bottom:6px;">{icon}</div>
                    <div style="color:#2ecc71; font-weight:600; margin-bottom:4px;">{title}</div>
                    <div style="color:#8b949e; font-size:0.85rem; line-height:1.5;">{desc}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # ── PDF Export hint ───────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)
    st.info(
        "📄 **Export a PDF report** using the button in the sidebar to save your "
        "OWASP API Security summary for sharing with your team."
    )
