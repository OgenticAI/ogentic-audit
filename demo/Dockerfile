# ogentic-audit verify-chain demo (OGE-1668).
#
# Runs the PUBLISHED wheel — no Rust toolchain, no from-source build. The whole
# point of the demo is to show exactly what `pip install ogentic-audit` gives
# you, so we install that and nothing more.
FROM python:3.12-slim

WORKDIR /app

COPY demo/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY demo/ ./demo/

EXPOSE 8501

# $PORT is provided by the platform (Railway); default to 8501 locally.
ENV PORT=8501
CMD ["sh", "-c", "streamlit run demo/app.py --server.port=${PORT} --server.address=0.0.0.0 --server.headless=true"]
