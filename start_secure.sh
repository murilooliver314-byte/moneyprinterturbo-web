#!/bin/bash
set -euo pipefail
: "${AUTH_USER:?AUTH_USER precisa estar configurado}"
: "${AUTH_PASSWORD:?AUTH_PASSWORD precisa estar configurado}"
PORT="${PORT:-10000}"
htpasswd -bc /etc/nginx/.htpasswd "$AUTH_USER" "$AUTH_PASSWORD"
envsubst '${PORT}' < /etc/nginx/templates/moneyprinterturbo.conf.template > /etc/nginx/conf.d/default.conf
python -m streamlit run ./webui/Main.py --server.address=127.0.0.1 --server.port=8501 --server.enableCORS=false --browser.gatherUsageStats=false --client.toolbarMode=minimal --server.showEmailPrompt=false &
STREAMLIT_PID=$!
nginx -g 'daemon off;' &
NGINX_PID=$!
wait -n "$STREAMLIT_PID" "$NGINX_PID"
