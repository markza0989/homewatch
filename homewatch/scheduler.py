#!/usr/bin/env python3
"""HomeWatch scanner process.

Runs the APScheduler jobs in a dedicated process — separate from Flask. This is
the *only* component that needs raw-socket capability (Scapy ARP / ICMP), so the
web app can run fully unprivileged. See README "Security design" and
THREAT_MODEL.md for the privilege-separation rationale.

Run it alongside the web app:

    # mock backend (no privileges needed) — great for dev/demo
    HOMEWATCH_SCAN_BACKEND=mock python scheduler.py

    # real ARP scanning — grant the venv python raw-socket capability first:
    #   sudo setcap cap_net_raw,cap_net_admin+ep $(readlink -f .venv/bin/python)
    HOMEWATCH_SCAN_BACKEND=scapy python scheduler.py
"""
import logging
from datetime import datetime, timezone

from dotenv import load_dotenv

load_dotenv()

from apscheduler.schedulers.blocking import BlockingScheduler  # noqa: E402

from app import create_app  # noqa: E402
from app.scanner.jobs import run_offline_job, run_scan_job  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("homewatch.scheduler")


def main() -> None:
    app = create_app()
    backend = app.config.get("SCAN_BACKEND")

    log.info("HomeWatch scanner starting (backend=%s)", backend)
    if backend == "scapy":
        log.info(
            "Real ARP scanning requires CAP_NET_RAW. If you see permission "
            "errors, run: sudo setcap cap_net_raw,cap_net_admin+ep "
            "$(readlink -f .venv/bin/python)"
        )

    scheduler = BlockingScheduler(timezone="UTC")
    # First scan fires immediately so the dashboard populates without waiting 60s.
    scheduler.add_job(
        run_scan_job,
        "interval",
        seconds=60,
        args=[app],
        id="arp_scan",
        max_instances=1,
        coalesce=True,
        # Timezone-aware so it matches the scheduler's UTC clock and fires now,
        # not (now interpreted as UTC) hours away.
        next_run_time=datetime.now(timezone.utc),
    )
    scheduler.add_job(
        run_offline_job,
        "interval",
        seconds=30,
        args=[app],
        id="offline_sweep",
        max_instances=1,
        coalesce=True,
    )

    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        log.info("scanner shutting down")


if __name__ == "__main__":
    main()
