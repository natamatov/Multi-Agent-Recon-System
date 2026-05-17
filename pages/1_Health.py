"""Streamlit: страница healthcheck."""

import streamlit as st

from core.healthcheck import run_healthcheck

st.title("M.A.R.S. Health")
st.json(run_healthcheck())
