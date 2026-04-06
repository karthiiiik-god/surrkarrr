import streamlit as st
import pandas as pd
import plotly.express as px
import subprocess
from core.storage.database import Database

st.set_page_config (layout="wide", page_title="SurrKarr")
