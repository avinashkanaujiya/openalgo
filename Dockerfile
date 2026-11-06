# ------------------------------ Python Builder Stage ----------------------- #
# Base images track Debian 13 "trixie". Debian 11 "bullseye" reached end of LTS
# on 2026-08-31 and its security pool was drained days later, so every build
# began failing with 404s on systemd, tzdata, libtiff5 and libgbm1 while the
# package index still advertised them. Debian 12 "bookworm" is not the fix --
# its regular security support ended 2026-07-11 and it is already LTS-only.
# Trixie has security support to 2028-08-09 (LTS to 2030-06-30).
FROM python:3.12-trixie AS python-builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl build-essential && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml .
# create isolated virtual-env with uv, then add gunicorn and eventlet with compatible versions
RUN pip install --no-cache-dir uv && \
    uv venv .venv && \
    uv pip install --upgrade pip && \
    uv sync && \
    uv pip install "gunicorn>=25.0,<26" "eventlet==0.41.2" && \
    rm -rf /root/.cache

# ------------------------------ Frontend Builder Stage --------------------- #
FROM node:22-trixie-slim AS frontend-builder
WORKDIR /app
COPY frontend/package*.json ./frontend/
RUN cd frontend && npm ci
COPY frontend/ ./frontend/
RUN cd frontend && npm run build

# --------------------------------------------------------------------------- #
# ------------------------------ Production Stage --------------------------- #
FROM python:3.12-slim-trixie AS production
# 0 – set timezone to IST (Asia/Kolkata) & install runtime dependencies
#     chromium + fonts-liberation are required by Kaleido 1.x (plotly static
#     image export) which drives a real headless Chromium via choreographer.
#     Without these, /chart in the Telegram bot silently fails inside Docker.
RUN apt-get update && apt-get install -y --no-install-recommends \
    tzdata \
    curl \
    libopenblas0 \
    libgomp1 \
    libgfortran5 \
    chromium \
    fonts-liberation && \
    ln -fs /usr/share/zoneinfo/Asia/Kolkata /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata && \
    apt-get clean && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# 2 – copy ready-made venv and application source
COPY --from=python-builder /app/.venv /app/.venv
COPY . .
# 3 – copy built frontend from frontend-builder
COPY --from=frontend-builder /app/frontend/dist /app/frontend/dist
# 4 – create required directories and restrict secrets
RUN mkdir -p /app/log /app/log/strategies /app/db /app/tmp /app/tmp/numba_cache /app/tmp/matplotlib /app/strategies /app/strategies/scripts /app/strategies/examples /app/keys && \
    chmod -R 755 /app/strategies /app/log /app/tmp && \
    chmod 700 /app/keys && \
    touch /app/.env && chmod 600 /app/.env
# 5 – entrypoint script and fix line endings
#     start.sh runs the web server launcher and its helpers when .env asks for
#     gthread, so they lose any Windows line endings too (bash cannot run them).
COPY start.sh /app/start.sh
RUN sed -i 's/\r$//' /app/start.sh /app/install/openalgo-gunicorn.sh \
        /app/install/lib/resolve_runtime.py /app/install/lib/gunicorn_hooks.py && \
    chmod +x /app/start.sh
# ---- RUNTIME ENVS --------------------------------------------------------- #
# Limit OpenBLAS/NumPy threads to prevent RLIMIT_NPROC exhaustion in Docker
# See: https://github.com/marketcalls/openalgo/issues/822
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TZ=Asia/Kolkata \
    APP_MODE=standalone \
    TMPDIR=/app/tmp \
    NUMBA_CACHE_DIR=/app/tmp/numba_cache \
    LLVMLITE_TMPDIR=/app/tmp \
    MPLCONFIGDIR=/app/tmp/matplotlib \
    OPENBLAS_NUM_THREADS=2 \
    OMP_NUM_THREADS=2 \
    MKL_NUM_THREADS=2 \
    NUMEXPR_NUM_THREADS=2 \
    NUMBA_NUM_THREADS=2 \
    BROWSER_PATH=/usr/bin/chromium \
    CHROME_BIN=/usr/bin/chromium
# --------------------------------------------------------------------------- #
EXPOSE 5000
CMD ["/app/start.sh"]
