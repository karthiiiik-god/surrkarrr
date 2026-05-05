from __future__ import annotations

from html import escape
from textwrap import dedent

import plotly.graph_objects as go
import streamlit as st


CHART_COLORS = {
    "Critical": "#d95f4b",
    "High": "#ef9f45",
    "Medium": "#4f83cc",
    "Low": "#48a87d",
}


def apply_theme() -> None:
    _render_html(
        """
        <style>
        :root {
            --sk-bg: #fffaf4;
            --sk-surface: rgba(255, 255, 255, 0.82);
            --sk-surface-strong: #ffffff;
            --sk-surface-soft: #fff3df;
            --sk-border: rgba(212, 170, 103, 0.24);
            --sk-text: #263238;
            --sk-text-soft: #5d6d75;
            --sk-primary: #0f7b6c;
            --sk-primary-soft: #dff4ef;
            --sk-accent: #f4a261;
            --sk-accent-soft: #fff0df;
            --sk-danger: #cf5c4e;
            --sk-radius-lg: 24px;
            --sk-radius-md: 18px;
            --sk-shadow: 0 24px 54px rgba(197, 165, 114, 0.12);
        }

        .stApp {
            background:
                radial-gradient(circle at top left, rgba(249, 199, 132, 0.28), transparent 32%),
                radial-gradient(circle at top right, rgba(111, 201, 185, 0.22), transparent 28%),
                linear-gradient(180deg, #fffaf4 0%, #fff7ee 38%, #fffdf9 100%);
            color: var(--sk-text);
        }

        .stApp, .stApp p, .stApp label, .stApp span, .stApp div, .stApp li {
            font-family: "Trebuchet MS", "Segoe UI", sans-serif;
        }

        .stApp h1, .stApp h2, .stApp h3 {
            font-family: Georgia, "Times New Roman", serif;
            letter-spacing: -0.02em;
            color: #173042;
        }

        .block-container {
            padding-top: 2rem;
            padding-bottom: 3rem;
        }

        [data-testid="stSidebar"] {
            background:
                linear-gradient(180deg, rgba(255, 248, 238, 0.97) 0%, rgba(255, 243, 224, 0.94) 100%);
            border-right: 1px solid var(--sk-border);
        }

        [data-testid="stSidebar"] .block-container {
            padding-top: 1.4rem;
        }

        [data-testid="stMetric"] {
            background: var(--sk-surface);
            border: 1px solid var(--sk-border);
            border-radius: var(--sk-radius-md);
            padding: 1rem 1rem 0.85rem 1rem;
            box-shadow: var(--sk-shadow);
        }

        [data-testid="stMetricLabel"] {
            color: var(--sk-text-soft);
            font-weight: 600;
        }

        [data-testid="stMetricValue"] {
            color: #173042;
            font-family: Georgia, "Times New Roman", serif;
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 0.5rem;
            background: rgba(255,255,255,0.42);
            padding: 0.45rem;
            border-radius: 999px;
            border: 1px solid var(--sk-border);
        }

        .stTabs [data-baseweb="tab"] {
            border-radius: 999px;
            padding: 0.55rem 1rem;
            color: var(--sk-text-soft);
            font-weight: 600;
        }

        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, #0f7b6c 0%, #2e9d90 100%);
            color: white;
        }

        .stButton > button,
        .stDownloadButton > button {
            border-radius: 999px;
            border: 1px solid rgba(15, 123, 108, 0.18);
            background: linear-gradient(135deg, #0f7b6c 0%, #2d9387 100%);
            color: white;
            font-weight: 700;
            padding: 0.55rem 1.15rem;
            box-shadow: 0 14px 28px rgba(15, 123, 108, 0.18);
        }

        .stButton > button[kind="secondary"],
        .stDownloadButton > button[kind="secondary"] {
            background: white;
            color: var(--sk-primary);
        }

        .stTextInput input,
        .stTextArea textarea,
        .stNumberInput input,
        div[data-baseweb="select"] > div,
        .stDateInput input {
            background: rgba(255, 255, 255, 0.9);
            border-radius: 16px;
            border: 1px solid var(--sk-border);
        }

        .stTextInput input:focus,
        .stTextArea textarea:focus,
        .stNumberInput input:focus {
            border-color: rgba(15, 123, 108, 0.45);
            box-shadow: 0 0 0 1px rgba(15, 123, 108, 0.2);
        }

        [data-testid="stDataFrame"],
        [data-testid="stExpander"],
        .stAlert,
        [data-testid="stCodeBlock"] {
            border-radius: var(--sk-radius-md);
            overflow: hidden;
            border: 1px solid var(--sk-border);
            box-shadow: 0 16px 36px rgba(217, 185, 134, 0.12);
        }

        [data-testid="stExpander"] {
            background: rgba(255, 255, 255, 0.72);
        }

        .sk-shell {
            background: linear-gradient(135deg, rgba(255,255,255,0.88) 0%, rgba(255,243,223,0.96) 100%);
            border: 1px solid var(--sk-border);
            border-radius: 28px;
            padding: 1.35rem 1.45rem;
            box-shadow: var(--sk-shadow);
        }

        .sk-brand {
            background: linear-gradient(135deg, rgba(15,123,108,0.12) 0%, rgba(244,162,97,0.16) 100%);
            border: 1px solid rgba(15,123,108,0.13);
            border-radius: 24px;
            padding: 1rem 1rem 1.05rem 1rem;
            margin-bottom: 1rem;
        }

        .sk-brand h2 {
            margin: 0;
            font-size: 1.35rem;
        }

        .sk-kicker {
            text-transform: uppercase;
            letter-spacing: 0.12em;
            font-size: 0.72rem;
            color: var(--sk-primary);
            font-weight: 800;
            margin-bottom: 0.45rem;
        }

        .sk-hero {
            background:
                linear-gradient(135deg, rgba(255,255,255,0.86) 0%, rgba(255,240,223,0.92) 56%, rgba(223,244,239,0.88) 100%);
            border: 1px solid var(--sk-border);
            border-radius: 28px;
            padding: 1.7rem 1.8rem;
            box-shadow: var(--sk-shadow);
            margin-bottom: 1.25rem;
        }

        .sk-hero h1, .sk-hero h2 {
            margin: 0 0 0.3rem 0;
        }

        .sk-hero p {
            margin: 0;
            color: var(--sk-text-soft);
            line-height: 1.6;
        }

        .sk-pill-row {
            display: flex;
            flex-wrap: wrap;
            gap: 0.55rem;
            margin-top: 1rem;
        }

        .sk-pill {
            background: rgba(255,255,255,0.8);
            border: 1px solid rgba(15,123,108,0.13);
            border-radius: 999px;
            color: var(--sk-text);
            font-size: 0.86rem;
            padding: 0.42rem 0.8rem;
        }

        .sk-card {
            background: var(--sk-surface);
            border: 1px solid var(--sk-border);
            border-radius: var(--sk-radius-lg);
            padding: 1.1rem 1.15rem;
            box-shadow: 0 18px 38px rgba(217, 185, 134, 0.12);
        }

        .sk-card h3 {
            margin-top: 0;
            margin-bottom: 0.3rem;
            font-size: 1.15rem;
        }

        .sk-card p, .sk-card li {
            color: var(--sk-text-soft);
        }

        .sk-stat-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 0.85rem;
            margin: 1rem 0 0.1rem 0;
        }

        .sk-stat {
            background: rgba(255, 255, 255, 0.8);
            border-radius: 22px;
            padding: 1rem;
            border: 1px solid rgba(15,123,108,0.08);
        }

        .sk-stat-label {
            font-size: 0.8rem;
            color: var(--sk-text-soft);
            text-transform: uppercase;
            letter-spacing: 0.08em;
            margin-bottom: 0.35rem;
        }

        .sk-stat-value {
            font-size: 1.65rem;
            color: #173042;
            font-family: Georgia, "Times New Roman", serif;
            margin-bottom: 0.25rem;
        }

        .sk-stat-note {
            font-size: 0.85rem;
            color: var(--sk-text-soft);
        }

        .sk-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 0.95rem;
        }
        </style>
        """
    )


def sidebar_brand(user: dict[str, str], summary: dict, inventory: list[dict[str, object]]) -> None:
    pills = "".join(
        [
            _pill(f"Findings {summary['total']}"),
            _pill(f"Assets {summary['unique_assets']}"),
            _pill(f"Scan Jobs {summary['scan_count']}"),
        ]
    )
    inventory_markup = "".join(
        f"<div class='sk-pill'>{escape(str(item['scanner']))}: {'online' if item['available'] else 'offline'}</div>"
        for item in inventory
    )
    st.sidebar.markdown(
        dedent(
            f"""
            <div class="sk-brand">
                <div class="sk-kicker">Defensive Command Center</div>
                <h2>SurrKarr</h2>
                <p style="margin:0.45rem 0 0 0;color:#5d6d75;">
                    Role-based vulnerability intelligence for authorized asset defense.
                </p>
                <div class="sk-pill-row">
                    {_pill(f"{user['username']}")}
                    {_pill(user['role'].title())}
                </div>
                <div class="sk-pill-row">{pills}</div>
            </div>
            <div class="sk-card" style="margin-bottom:1rem;">
                <h3 style="font-size:1rem;">Scanner Availability</h3>
                <div class="sk-pill-row">{inventory_markup}</div>
            </div>
            """
        ).strip(),
        unsafe_allow_html=True,
    )


def page_hero(title: str, description: str, *, kicker: str = "SurrKarr", pills: list[str] | None = None) -> None:
    pill_row = ""
    if pills:
        pill_row = f"<div class='sk-pill-row'>{''.join(_pill(item) for item in pills)}</div>"
    _render_html(
        f"""
        <div class="sk-hero">
            <div class="sk-kicker">{escape(kicker)}</div>
            <h1>{escape(title)}</h1>
            <p>{escape(description)}</p>
            {pill_row}
        </div>
        """
    )


def stat_tiles(items: list[tuple[str, str, str]]) -> None:
    tiles = "".join(
        (
            f"<div class=\"sk-stat\">"
            f"<div class=\"sk-stat-label\">{escape(label)}</div>"
            f"<div class=\"sk-stat-value\">{escape(value)}</div>"
            f"<div class=\"sk-stat-note\">{escape(note)}</div>"
            f"</div>"
        )
        for label, value, note in items
    )
    _render_html(f"<div class='sk-shell'><div class='sk-stat-grid'>{tiles}</div></div>")


def info_cards(cards: list[tuple[str, str]]) -> None:
    markup = "".join(
        (
            f"<div class=\"sk-card\">"
            f"<h3>{escape(title)}</h3>"
            f"<p>{escape(body)}</p>"
            f"</div>"
        )
        for title, body in cards
    )
    _render_html(f"<div class='sk-grid'>{markup}</div>")


def style_figure(fig: go.Figure, *, title: str | None = None) -> go.Figure:
    fig.update_layout(
        title=title or fig.layout.title.text,
        paper_bgcolor="rgba(255,255,255,0)",
        plot_bgcolor="rgba(255,255,255,0)",
        font={"family": "Trebuchet MS, Segoe UI, sans-serif", "color": "#31444c"},
        title_font={"family": "Georgia, Times New Roman, serif", "size": 20, "color": "#173042"},
        margin={"l": 20, "r": 20, "t": 55, "b": 20},
    )
    fig.update_xaxes(showgrid=False, zeroline=False)
    fig.update_yaxes(gridcolor="rgba(92, 121, 139, 0.14)", zeroline=False)
    return fig


def panel(title: str, body: str) -> None:
    _render_html(
        f"""
        <div class="sk-card">
            <h3>{escape(title)}</h3>
            <p>{escape(body)}</p>
        </div>
        """
    )


def _pill(value: str) -> str:
    return f"<span class='sk-pill'>{escape(value)}</span>"


def _render_html(html: str) -> None:
    st.markdown(dedent(html).strip(), unsafe_allow_html=True)
