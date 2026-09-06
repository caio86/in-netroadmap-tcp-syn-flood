#!/bin/bash
echo $SRV > /tmp/get_cpu_manifest

CSV_FILE="/tmp/cpu_metrics_$SRV-$(date +"%Y%m%d_%H%M%S").csv"
INTERVAL=1
IS_RUNNING=true

if [ ! -f "$CSV_FILE" ]; then
	echo "timestamp,cpu_total_pct,cpu_user_pct,cpu_sys_pct" > "$CSV_FILE"
fi

cleanup() {
	echo "Saved file to $CSV_FILE"
	IS_RUNNING=false
	exit 0
}

trap cleanup SIGINT SIGTERM

calc_pct() {
	local start=$1
	local end=$2
	local secs=$3

	awk -v start="$start" -v end="$end" -v secs="$secs" 'BEGIN {
		delta = end - start
		if (delta < 0) delta = 0
		printf "%.2f\n", delta / (secs * 10000)
	}'
}

fetch_metric() {
	local key=$1
	grep -w "$key" /sys/fs/cgroup/cpu.stat | awk '{print $2}'
}

TOTAL_PREV=$(fetch_metric "usage_usec")
USER_PREV=$(fetch_metric "user_usec")
SYS_PREV=$(fetch_metric "system_usec")

while [ "$IS_RUNNING" = true ]; do
sleep $INTERVAL
	TIMESTAMP=$(date +%s%3N)

	TOTAL_CURR=$(fetch_metric "usage_usec")
	USER_CURR=$(fetch_metric "user_usec")
	SYS_CURR=$(fetch_metric "system_usec")

	PCT_TOTAL=$(calc_pct "$TOTAL_PREV" "$TOTAL_CURR" "$INTERVAL")
	PCT_USER=$(calc_pct "$USER_PREV" "$USER_CURR" "$INTERVAL")
	PCT_SYS=$(calc_pct "$SYS_PREV" "$SYS_CURR" "$INTERVAL")

	echo "$TIMESTAMP,$PCT_TOTAL,$PCT_USER,$PCT_SYS" >> "$CSV_FILE"

	TOTAL_PREV=$TOTAL_CURR
	USER_PREV=$USER_CURR
	SYS_PREV=$SYS_CURR
done

