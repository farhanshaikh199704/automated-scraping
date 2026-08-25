#!/usr/bin/env bash
# Provision a fresh Ubuntu 24.04 VPS for scheduled collection.
# Run as a normal sudo-capable user, not as root.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "== System packages =="
sudo apt-get update
sudo apt-get install -y \
    python3 python3-venv python3-pip \
    xvfb x11vnc \
    fonts-liberation fonts-noto-color-emoji \
    ca-certificates curl

echo "== Python environment =="
python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install --upgrade pip
"$APP_DIR/.venv/bin/pip" install playwright pyyaml pyotp

echo "== Chromium =="
# --with-deps pulls the shared libraries Chromium needs on a headless server.
"$APP_DIR/.venv/bin/playwright" install --with-deps chromium

echo "== Timezone =="
# Keep the box on UTC so cron times mean one unambiguous thing.
sudo timedatectl set-timezone UTC

cat <<EOF

Setup complete.

1. Confirm the exit IP is Swedish:

     $APP_DIR/.venv/bin/python $APP_DIR/run.py --check-geo

2. Smoke-test the harness without touching any real service. Set
   'adapter: smoke' in config.yaml, then:

     xvfb-run -a $APP_DIR/.venv/bin/python $APP_DIR/run.py

3. Sign in once, interactively. The VPS has no display, so forward one
   over SSH from your Mac (needs XQuartz installed locally):

     ssh -X user@your-vps
     $APP_DIR/.venv/bin/python $APP_DIR/run.py --login

   If X forwarding is awkward, the alternative is x11vnc against an Xvfb
   display, tunnelled over SSH:

     Xvfb :99 -screen 0 1440x900x24 &
     x11vnc -display :99 -localhost -nopw -forever &
     # then from your Mac: ssh -L 5900:localhost:5900 user@your-vps
     # and connect a VNC client to localhost:5900
     DISPLAY=:99 $APP_DIR/.venv/bin/python $APP_DIR/run.py --login

4. Schedule it. Times are UTC. This example runs Mondays and Thursdays
   at 09:00 and 17:00 UTC:

     crontab -e

     0 9,17 * * 1,4 cd $APP_DIR && xvfb-run -a $APP_DIR/.venv/bin/python $APP_DIR/run.py >> $APP_DIR/cron.log 2>&1

   Adjust the day and hour fields to your schedule. Note that Stockholm
   is UTC+2 in summer and UTC+1 in winter, so a fixed UTC time drifts by
   an hour across the DST boundary. Pick UTC and keep it constant if the
   comparison against the API arm matters; pick local time via
   CRON_TZ=Europe/Stockholm at the top of the crontab if wall-clock time
   is what matters.

5. Guard against silent failure. Set failure_webhook in config.yaml, or
   check that a new directory appears under runs/ after each scheduled
   time.

EOF
