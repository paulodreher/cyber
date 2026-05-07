"""Q&A chat panel component."""

from __future__ import annotations
import streamlit as st
from data.knowledge_base import KnowledgeBase

_kb = KnowledgeBase()

# Suggested quick-question chips
SUGGESTIONS = [
    "What is BOLA?",
    "How do I prevent SSRF?",
    "JWT best practices",
    "What is OWASP ASVS?",
    "Mass assignment fix",
    "Rate limiting tips",
    "CORS configuration",
    "What should APIs log?",
    "OAuth 2.0 flows",
]


def _init_chat_history() -> None:
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = [
            {
                "role": "assistant",
                "content": (
                    "### Hi! I'm your OWASP API Security Assistant 👋\n\n"
                    "Ask me anything about API security, vulnerabilities, "
                    "secure coding, JWT, OAuth, CORS, or any OWASP topic.\n\n"
                    "You can also click one of the quick questions below to get started!"
                ),
            }
        ]


def render_qa_panel() -> None:
    """Render the full Q&A chat interface."""
    _init_chat_history()

    st.markdown(
        """
        <div style="
            background: linear-gradient(135deg, #0f1923 0%, #1a2535 100%);
            border: 1px solid #3498db44;
            border-radius: 12px;
            padding: 20px 24px;
            margin-bottom: 20px;
        ">
            <h2 style="color: #3498db; margin: 0 0 6px 0; font-family: 'Courier New', monospace;">
                💬 Ask the Security Assistant
            </h2>
            <span style="color: #8b949e; font-size: 0.9rem;">
                Powered by an internal OWASP knowledge base — no external API required.
            </span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # ── Quick suggestion chips ───────────────────────────────────────────────
    st.markdown(
        "<p style='color:#8b949e; font-size:0.85rem; margin-bottom:6px;'>Quick questions:</p>",
        unsafe_allow_html=True,
    )
    cols = st.columns(3)
    for i, suggestion in enumerate(SUGGESTIONS):
        with cols[i % 3]:
            if st.button(
                suggestion,
                key=f"suggest_{i}",
                use_container_width=True,
            ):
                _handle_query(suggestion)

    st.divider()

    # ── Chat history ─────────────────────────────────────────────────────────
    chat_container = st.container()
    with chat_container:
        for msg in st.session_state.chat_history:
            _render_message(msg)

    # ── Input bar ────────────────────────────────────────────────────────────
    st.markdown("<br>", unsafe_allow_html=True)

    with st.form(key="qa_form", clear_on_submit=True):
        col_input, col_btn = st.columns([5, 1])
        with col_input:
            user_input = st.text_input(
                "Your question",
                placeholder="e.g. How do I fix BOLA? What is JWT algorithm confusion?",
                label_visibility="collapsed",
            )
        with col_btn:
            submitted = st.form_submit_button("Ask ➤", use_container_width=True)

    if submitted and user_input.strip():
        _handle_query(user_input.strip())

    # ── Clear history button ─────────────────────────────────────────────────
    if len(st.session_state.chat_history) > 1:
        if st.button("🗑️ Clear chat history", key="clear_chat"):
            st.session_state.chat_history = []
            _init_chat_history()
            st.rerun()


def _handle_query(query: str) -> None:
    """Process a user query, append to history, and rerun."""
    # Add user message
    st.session_state.chat_history.append({"role": "user", "content": query})

    # Get answer from knowledge base
    answer = _kb.answer(query)

    # Add assistant response
    st.session_state.chat_history.append({"role": "assistant", "content": answer})

    st.rerun()


def _render_message(msg: dict) -> None:
    """Render a single chat message bubble."""
    role = msg["role"]
    content = msg["content"]

    if role == "user":
        st.markdown(
            f"""
            <div style="
                display: flex;
                justify-content: flex-end;
                margin-bottom: 12px;
            ">
                <div style="
                    background: #1e3a5f;
                    border: 1px solid #3498db55;
                    border-radius: 16px 16px 4px 16px;
                    padding: 12px 16px;
                    max-width: 75%;
                    color: #e6edf3;
                    font-size: 0.95rem;
                ">
                    <span style="font-size:0.75rem; color:#3498db; display:block; margin-bottom:4px;">
                        👤 You
                    </span>
                    {content}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div style="
                display: flex;
                justify-content: flex-start;
                margin-bottom: 12px;
            ">
                <div style="
                    background: #0f2318;
                    border: 1px solid #2ecc7144;
                    border-radius: 16px 16px 16px 4px;
                    padding: 12px 16px;
                    max-width: 85%;
                    color: #c9d1d9;
                    font-size: 0.95rem;
                ">
                    <span style="font-size:0.75rem; color:#2ecc71; display:block; margin-bottom:6px;">
                        🤖 Security Assistant
                    </span>
            """,
            unsafe_allow_html=True,
        )
        # Render markdown content properly
        st.markdown(content)
        st.markdown("</div></div>", unsafe_allow_html=True)
