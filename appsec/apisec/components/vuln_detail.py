"""Renders the detailed view for a single OWASP API vulnerability."""

from __future__ import annotations
import streamlit as st


# Map risk rating to a colored badge
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

# Language → Streamlit syntax highlight token
LANG_HIGHLIGHT = {
    "Python (Flask)":       "python",
    "JavaScript (Express)": "javascript",
    "Java (Spring Boot)":   "java",
    "Go":                   "go",
    "PHP (Laravel)":        "php",
    "Ruby (Rails)":         "ruby",
    "C# (.NET)":            "csharp",
    "Kotlin (Ktor)":        "kotlin",
}


def _lang_token(lang: str) -> str:
    for key, token in LANG_HIGHLIGHT.items():
        if key.lower() in lang.lower():
            return token
    return "text"


def render_vuln_detail(vuln: dict) -> None:
    """Render all tabs for a single vulnerability entry."""

    risk = vuln.get("risk_rating", "Medium")
    color = RISK_COLORS.get(risk, "#f1c40f")
    icon = RISK_ICONS.get(risk, "🟡")

    # ── Header ──────────────────────────────────────────────────────────────
    st.markdown(
        f"""
        <div style="
            background: linear-gradient(135deg, #0f1923 0%, #1a2535 100%);
            border: 1px solid {color};
            border-radius: 12px;
            padding: 24px 28px;
            margin-bottom: 20px;
            box-shadow: 0 0 24px {color}33;
        ">
            <h2 style="color: {color}; margin: 0 0 8px 0; font-family: 'Courier New', monospace;">
                {icon} {vuln['title']}
            </h2>
            <span style="
                background-color: {color};
                color: #0f1923;
                padding: 3px 12px;
                border-radius: 20px;
                font-size: 0.8rem;
                font-weight: 700;
                letter-spacing: 1px;
            ">RISK: {risk.upper()}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Short description
    st.markdown(
        f"""
        <div style="
            background: #1a2535;
            border-left: 4px solid {color};
            padding: 14px 18px;
            border-radius: 0 8px 8px 0;
            margin-bottom: 24px;
            color: #c9d1d9;
            font-size: 1.05rem;
            line-height: 1.6;
        ">
            {vuln['short_desc']}
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Tabs ────────────────────────────────────────────────────────────────
    tab_vuln, tab_secure, tab_attack, tab_prop, tab_refs = st.tabs([
        "💀 Vulnerable Code",
        "🛡️ Secure Code",
        "⚡ Attack (curl)",
        "🌐 Propagation",
        "📚 References",
    ])

    # ── Tab 1: Vulnerable Code ───────────────────────────────────────────────
    with tab_vuln:
        st.markdown(
            """
            <div style="background:#2d1515; border:1px solid #e74c3c33;
                        border-radius:8px; padding:12px 16px; margin-bottom:16px;">
                <b style="color:#e74c3c;">⚠️ What NOT to do</b>
                <span style="color:#8b949e; margin-left:8px; font-size:0.9rem;">
                    — These patterns make your API vulnerable. Study them to recognize and avoid them.
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        langs = list(vuln.get("vulnerable_code", {}).keys())
        if langs:
            selected_lang = st.selectbox(
                "Select language",
                langs,
                key=f"vuln_lang_{vuln['id']}",
            )
            code = vuln["vulnerable_code"][selected_lang]
            st.code(code, language=_lang_token(selected_lang))

    # ── Tab 2: Secure Code ───────────────────────────────────────────────────
    with tab_secure:
        st.markdown(
            """
            <div style="background:#0d2818; border:1px solid #2ecc7133;
                        border-radius:8px; padding:12px 16px; margin-bottom:16px;">
                <b style="color:#2ecc71;">✅ What TO do</b>
                <span style="color:#8b949e; margin-left:8px; font-size:0.9rem;">
                    — Production-ready secure implementations with inline comments.
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        langs = list(vuln.get("secure_code", {}).keys())
        if langs:
            selected_lang = st.selectbox(
                "Select language",
                langs,
                key=f"sec_lang_{vuln['id']}",
            )
            code = vuln["secure_code"][selected_lang]
            st.code(code, language=_lang_token(selected_lang))

    # ── Tab 3: Attack ────────────────────────────────────────────────────────
    with tab_attack:
        st.markdown(
            """
            <div style="background:#1a1a2e; border:1px solid #9b59b633;
                        border-radius:8px; padding:12px 16px; margin-bottom:16px;">
                <b style="color:#9b59b6;">⚡ Attack Simulation</b>
                <span style="color:#8b949e; margin-left:8px; font-size:0.9rem;">
                    — Real curl commands showing how these vulnerabilities are exploited.
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        attacks = vuln.get("curl_attacks", [])
        if not attacks:
            st.info("No attack examples available for this vulnerability.")
        else:
            for i, attack in enumerate(attacks, 1):
                with st.expander(f"Attack {i}: {attack['title']}", expanded=(i == 1)):
                    st.code(attack["command"], language="bash")
                    st.markdown(
                        f"""
                        <div style="
                            background:#1e2d1e;
                            border-left:3px solid #f39c12;
                            padding:10px 14px;
                            border-radius:0 6px 6px 0;
                            color:#f39c12;
                            font-size:0.95rem;
                            margin-top:8px;
                        ">
                            💡 <b>How it works:</b> {attack['explanation']}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

    # ── Tab 4: Propagation ───────────────────────────────────────────────────
    with tab_prop:
        st.markdown(
            """
            <div style="background:#1a1500; border:1px solid #f39c1233;
                        border-radius:8px; padding:12px 16px; margin-bottom:20px;">
                <b style="color:#f39c12;">🌐 Attack Propagation & Business Impact</b>
                <span style="color:#8b949e; margin-left:8px; font-size:0.9rem;">
                    — How the attack spreads from initial exploit to full compromise.
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        propagation = vuln.get("propagation", "")

        # Render the propagation flowchart using Streamlit metrics/columns
        _render_propagation_flow(propagation, color)

    # ── Tab 5: References ────────────────────────────────────────────────────
    with tab_refs:
        st.markdown(
            """
            <div style="background:#0f1923; border:1px solid #3498db33;
                        border-radius:8px; padding:12px 16px; margin-bottom:20px;">
                <b style="color:#3498db;">📚 Authoritative References</b>
                <span style="color:#8b949e; margin-left:8px; font-size:0.9rem;">
                    — OWASP, ASVS, Cheat Sheets, and more.
                </span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        refs = vuln.get("references", [])
        for ref in refs:
            st.markdown(
                f"""
                <a href="{ref['url']}" target="_blank" style="
                    display:block;
                    background:#1a2535;
                    border:1px solid #3498db44;
                    border-radius:8px;
                    padding:12px 16px;
                    margin-bottom:8px;
                    color:#3498db;
                    text-decoration:none;
                    transition:all 0.2s;
                ">
                    🔗 {ref['title']}
                    <span style="color:#4a5568; font-size:0.8rem; display:block; margin-top:2px;">
                        {ref['url']}
                    </span>
                </a>
                """,
                unsafe_allow_html=True,
            )


def _render_propagation_flow(propagation_text: str, accent_color: str) -> None:
    """Render propagation as both markdown and a visual flow diagram."""
    import streamlit as st

    # Parse steps from the markdown text (lines starting with **)
    lines = propagation_text.strip().split("\n\n")
    steps = []
    for line in lines:
        line = line.strip()
        if line.startswith("**"):
            # Extract step title and body
            end_bold = line.find("**", 2)
            if end_bold != -1:
                title = line[2:end_bold]
                body = line[end_bold + 2:].strip().lstrip(":").strip()
                steps.append({"title": title, "body": body})
            else:
                steps.append({"title": line, "body": ""})
        elif line:
            steps.append({"title": "", "body": line})

    if not steps:
        st.markdown(propagation_text)
        return

    # Visual flow
    step_colors = [
        "#e74c3c",  # red
        "#e67e22",  # orange
        "#f1c40f",  # yellow
        "#2ecc71",  # green
        "#3498db",  # blue
        "#9b59b6",  # purple
    ]

    for i, step in enumerate(steps):
        c = step_colors[i % len(step_colors)]
        title = step["title"]
        body = step["body"]
        if not title and not body:
            continue

        col1, col2 = st.columns([1, 11])
        with col1:
            st.markdown(
                f"""
                <div style="
                    background:{c};
                    color:#0f1923;
                    width:36px;
                    height:36px;
                    border-radius:50%;
                    display:flex;
                    align-items:center;
                    justify-content:center;
                    font-weight:700;
                    font-size:1rem;
                    margin-top:8px;
                ">{i + 1}</div>
                """,
                unsafe_allow_html=True,
            )
        with col2:
            if title:
                st.markdown(
                    f"<b style='color:{c};'>{title}</b>",
                    unsafe_allow_html=True,
                )
            if body:
                st.markdown(
                    f"<span style='color:#c9d1d9; font-size:0.95rem;'>{body}</span>",
                    unsafe_allow_html=True,
                )

        # Arrow between steps (not after last)
        if i < len(steps) - 1:
            st.markdown(
                f"<div style='color:{c}; font-size:1.4rem; margin-left:10px;'>↓</div>",
                unsafe_allow_html=True,
            )
