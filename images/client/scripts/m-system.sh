#!/bin/bash



if [ -z "$1" ]; then
    echo "Usage: $0 <duration_in_seconds>"
    echo "Example: $0 60 (runs for 1 minute)"
    exit 1
fi

DURATION=$1
CPU_PID=""
MEM_PID=""
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
: "${SRV:="other"}" && export SRV

echo $SRV >> /tmp/m-server-manifest

cleanup() {
    echo -e "\n[Wrapper] Interrupt signal received. Stopping all monitors..."
    
    if [ -n "$CPU_PID" ] && kill -0 "$CPU_PID" 2>/dev/null; then
        kill -15 "$CPU_PID"
    fi
    
    if [ -n "$MEM_PID" ] && kill -0 "$MEM_PID" 2>/dev/null; then
        kill -15 "$MEM_PID"
    fi

    echo "[Wrapper] All monitors stopped. Exiting."
    exit 0
}

trap cleanup SIGINT SIGTERM

run_monitoring() {
    local run_time=$1

    echo "[Wrapper] Starting CPU and Memory metrics collection..."

    $SCRIPT_DIR/server/get_cpu.sh &
    CPU_PID=$!
    
    $SCRIPT_DIR/server/get_memory.sh &
    MEM_PID=$!

    echo "[Wrapper] Monitors running in background (CPU PID: $CPU_PID | MEM PID: $MEM_PID)"
    echo "[Wrapper] Collection will automatically stop in $run_time seconds."

    sleep "$run_time"

    echo "[Wrapper] Time limit reached ($run_time seconds)."
    cleanup
}

run_monitoring "$DURATION"
