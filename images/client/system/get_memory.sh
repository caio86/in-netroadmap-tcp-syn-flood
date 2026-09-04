#!/bin/bash
echo $SRV > /tmp/get_memory_manifest

CSV_FILE="/tmp/memory_metrics_$SRV-$(date +"%Y%m%d_%H%M%S").csv"
LOG_INTERVAL=1
IS_RUNNING=true

if [ ! -f "$CSV_FILE" ]; then
	echo "timestamp,anon_bytes,file_bytes,sock_bytes" > "$CSV_FILE"
fi

cleanup() {
	IS_RUNNING=false
	echo "Saved file to $CSV_FILE"
	exit 0
}

trap cleanup SIGINT SIGTERM

while [ "$IS_RUNNING" = true ]; do
	TIMESTAMP=$(date +%s%3N)

	ANON=$(grep -w "anon" /sys/fs/cgroup/memory.stat | awk '{print $2}')
	FILE=$(grep -w "file" /sys/fs/cgroup/memory.stat | awk '{print $2}')
	SOCK=$(grep -w "sock" /sys/fs/cgroup/memory.stat | awk '{print $2}')
	SOCK=${SOCK:-0}

	echo "$TIMESTAMP,$ANON,$FILE,$SOCK" >> "$CSV_FILE"

	sleep $LOG_INTERVAL
done

