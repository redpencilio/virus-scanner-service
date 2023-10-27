#!/bin/bash

node -e "let pjson = require('./app/package.json'); console.log(pjson.name + ' ' + pjson.version)"


if [[ $VIRUS_SCANNER_CLAMD_USER ]]; then
  echo "VIRUS_SCANNER_CLAMD_USER: $VIRUS_SCANNER_CLAMD_USER"
  CLAMD_USER="$VIRUS_SCANNER_CLAMD_USER"
else
  echo "VIRUS_SCANNER_CLAMD_USER empty or not set. Using ClamAV default."
  CLAMD_USER="clamav"
fi

echo "Setting clamd user to $CLAMD_USER"
debconf-set-selections <<< "clamav-daemon clamav-daemon/User string $CLAMD_USER"
# > Just running dpkg-reconfigure clamav-daemon won't reset
# > /etc/clamav/clamd.conf to a debconf generated configuration file.
# -- /usr/share/doc/clamav-daemon/README.Debian.gz  (1.0.3)
CLAMD_CONF="/etc/clamav/clamd.conf"
if grep -q "^User\b" "$CLAMD_CONF"; then
  sed --in-place -e "s/^User\b.*/User $CLAMD_USER/" "$CLAMD_CONF"
else
  echo "User $CLAMD_USER" >> "$CLAMD_CONF"
fi
DEBIAN_FRONTEND=noninteractive dpkg-reconfigure clamav-daemon


# Wait for complete signature database before starting clamd.
echo "Initial run of freshclam"
freshclam

echo "(Re)starting clamav-daemon/clamd"
service clamav-daemon restart

echo "(Re)starting freshclam daemon"
service clamav-freshclam restart

echo "Starting boot.sh"
bash boot.sh
