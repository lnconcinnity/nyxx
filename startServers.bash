#!/bin/bash

dir="$(dirname "$0")"
logs_dir="${dir}"
backend_log_file="${logs_dir}/backend.log"
frontend_log_file="${logs_dir}/frontend.log"

mkdir -p "$logs_dir"

start_process() {
  local service_dir=$1
  local log_file=$2
  echo "Starting server for ${dir}"
  (cd "${dir}${service_dir}" && npm start >> "$log_file" 2>&1) &
  PIDS+=($!)
}

PIDS=()

start_process "/backend" "$backend_log_file"
start_process "/frontend" "$frontend_log_file"

stop_processes() {
  echo "Stopping servers..."
  for PID in "${PIDS[@]}"; do
    kill "$PID"
  done
  wait
  echo "Servers stopped"
  exit 0
}

trap stop_processes SIGINT

echo "Press Ctrl+C to stop the servers"
while :; do
  sleep 1
done