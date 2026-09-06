#!/bin/bash
DURATION=$1

SERVER=$2
STREAM_URL="http://$SERVER/videos/video.mpd"
WEB_URL="http://$SERVER/index.html"

FTP_USER="anonymous"
FTP_PASS="anonymous"
FILE_URL="ftp://$SERVER/JihanGrandTheater.jpg"

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_DIR="/tmp"
STREAM_LOG="$LOG_DIR/vlc-$TIMESTAMP.log"
WEB_LOG="$LOG_DIR/web-$TIMESTAMP.csv"
FILE_LOG="$LOG_DIR/file-$TIMESTAMP.csv"
IPERF_LOG="$LOG_DIR/iperf-$TIMESTAMP.json"

consume_web() {
    echo "http_status,time_total" > "$WEB_LOG"
    while true; do
        ts=$(date +%s.%3N)
        curl -so /dev/null "$WEB_URL" \
            --connect-timeout 2 --max-time 5 \
            -w "$ts,%{http_code},%{time_total}\n" >> "$WEB_LOG" || true
        sleep 1
    done
}

consume_file() {
    echo "time_total" > "$FILE_LOG"
    while true; do
        curl -so /dev/null -u "$FTP_USER:$FTP_PASS" "$FILE_URL" -w "%{time_total}\n" >> "$FILE_LOG" || true
        sleep 1
    done
}

consume_video() {
    while true; do
        cvlc -I dummy --no-audio --verbose=2 --vout=xcb_x11 --file-caching=5000 --network-caching=5000 "$STREAM_URL" vlc://quit >> "$STREAM_LOG" 2>&1
        sleep 1
    done
}

consume_iperf() {
	iperf3 -c $SERVER -t 0 --json --logfile "$IPERF_LOG" -l 500
}

cleanup() {
    echo -e "\nEncerrando todos os geradores de tráfego..."
    pkill -P $$ 2>/dev/null
    pkill -f "curl .*$WEB_URL" 2>/dev/null
    exit 0
}

trap cleanup SIGINT SIGTERM

consume_web &
WEB_PID=$!

# consume_file &
# FILE_PID=$!

# consume_video &
# STREAM_PID=$!

# consume_iperf &
# IPERF_PID=$!

sleep $DURATION
cleanup