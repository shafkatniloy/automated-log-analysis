import argparse
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import random
import uuid

SERVICES = ["payment-api", "order-service", "auth-service", "inventory-api", "gateway"]
USERS = ["alice", "bob", "carol", "admin", "service-account-01"]
IPS = ["192.0.2.10", "192.0.2.15", "198.51.100.22", "198.51.100.99", "203.0.113.45"]


def generate_logs(output_file: Path, total_lines: int = 200, include_anomalies: bool = True):
    output_file.parent.mkdir(parents=True, exist_ok=True)
    base_time = datetime.now(timezone.utc) - timedelta(minutes=30)

    events = []
    current_time = base_time

    for _ in range(total_lines):
        current_time += timedelta(seconds=random.randint(2, 15))
        service = random.choice(SERVICES)
        status_code = random.choice([200, 200, 200, 201, 204, 400, 404])
        level = "INFO" if status_code < 400 else "WARNING"

        event = {
            "timestamp": current_time.isoformat(),
            "level": level,
            "service": service,
            "event": "request_completed",
            "message": f"HTTP {status_code} on /api/v1/{service.split('-')[0]}",
            "status_code": status_code,
            "duration_ms": random.randint(20, 350),
            "request_id": f"req-{uuid.uuid4().hex[:6]}",
        }
        events.append(event)

    if include_anomalies:
        spike_time = base_time + timedelta(minutes=15)
        for j in range(4):
            events.append({
                "timestamp": (spike_time + timedelta(seconds=j * 15)).isoformat(),
                "level": "ERROR",
                "service": "payment-api",
                "event": "database_connection_failed",
                "message": "Could not connect to database: timeout connecting to primary-db:5432 after 5000ms",
                "request_id": f"req-{uuid.uuid4().hex[:6]}",
            })

        auth_time = base_time + timedelta(minutes=20)
        for _ in range(6):
            events.append({
                "timestamp": (auth_time + timedelta(seconds=random.randint(5, 20))).isoformat(),
                "level": "WARNING",
                "service": "auth-service",
                "event": "login_failed",
                "message": "Authentication attempt failed: invalid password for admin",
                "source_ip": "198.51.100.99",
                "user_id": "admin",
            })

    events.sort(key=lambda x: x["timestamp"])

    with open(output_file, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic demo logs.")
    parser.add_argument(
        "-o",
        "--output",
        default="./sample-logs/application/dynamic_demo.jsonl",
        help="Destination log file path.",
    )
    parser.add_argument(
        "-n",
        "--count",
        type=int,
        default=250,
        help="Number of log lines to generate.",
    )
    args = parser.parse_args()
    generate_logs(Path(args.output), total_lines=args.count)


if __name__ == "__main__":
    main()
