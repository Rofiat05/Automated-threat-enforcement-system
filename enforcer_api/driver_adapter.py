import sys
from pathlib import Path

# E's driver lives in <repo>/cisco_driver/com732_build/cisco_driver
DRIVER_FOLDER = Path(__file__).resolve().parents[1] / "cisco_driver" / "com732_build"


def load_driver():
    """Load E's driver without changing any of E's files."""
    folder = str(DRIVER_FOLDER)
    if folder not in sys.path:
        sys.path.insert(0, folder)
    from cisco_driver.client import DeviceError
    from cisco_driver.enforcer import block_approved
    return block_approved, DeviceError


def apply_block(decision, audit_path=None, client=None):
    """Turn C's decision into a request for E's driver.

    Returns {"status": "applied" | "already_applied" | "failed", "detail": ...}.
    It never raises: a problem on E's side must not crash the front door.
    """
    if not isinstance(decision, dict) or decision.get("action") != "block":
        return {"status": "failed", "detail": "not a block decision"}

    request = {
        "action": "block",
        "approved": True,  # set only here, after the front door accepted the alert
        "source_ip": decision.get("source_ip"),
        "ttl": decision.get("ttl_seconds"),  # E's driver calls it ttl
    }

    options = {}
    if audit_path is not None:
        options["audit_path"] = audit_path
    if client is not None:
        options["client"] = client

    try:
        block_approved, _ = load_driver()
        result = block_approved(request, **options)
    except Exception as error:
        return {"status": "failed",
                "detail": type(error).__name__ + ": " + str(error)}

    if result == "APPLIED":
        return {"status": "applied", "detail": "block added"}
    if result == "ALREADY_PRESENT":
        return {"status": "already_applied", "detail": "address was already blocked"}
    return {"status": "failed", "detail": "unexpected answer from the driver"}