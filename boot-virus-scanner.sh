#!/bin/bash

echo "Initial run of freshclam"
freshclam

echo "Starting clamav-daemon/clamd"
service clamav-daemon start

echo "Starting freshclam daemon"
service clamav-freshclam start

echo "Starting boot.sh"
bash boot.sh
