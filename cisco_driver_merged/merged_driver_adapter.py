import os
from pathlib import Path

from cisco_driver.driver import CiscoDriver
from cisco_driver.restconf_client import RestconfClient
from cisco_driver.store import BlockStore


BASE_FOLDER = Path(__file__).resolve().parent


def apply_block(decision, audit_path=None, client=None):
    """Connect an approved decision to the updated Cisco Driver."""

    if not isinstance(decision, dict):
        return {"status": "failed", "detail": "Invalid decision"}

    if decision.get("action") != "block":
        return {"status": "failed", "detail": "Not a block decision"}

    store = None

    try:
        ip = decision.get("source_ip")
        ttl = decision.get("ttl_seconds")
        device = decision.get("control_point", "mock-router-1")

        if not isinstance(device, str) or not device:
            return {"status": "failed", "detail": "Invalid device"}

        if client is None:
            client = RestconfClient(
                state_path=os.environ.get(
                    "MERGED_ACL_PATH",
                    str(BASE_FOLDER / "merged_acl_state.json")
                )
            )

        store = BlockStore(
            os.environ.get(
                "MERGED_DB_PATH",
                str(BASE_FOLDER / "merged_blocks.db")
            )
        )

        driver = CiscoDriver({device: client}, store)

        result = driver.block(ip, device, ttl)

        if result.status == "blocked":
            return {"status": "applied", "detail": "Block added"}

        if result.status == "already_blocked":
            return {
                "status": "already_applied",
                "detail": "Address already blocked",
            }

        return {
            "status": "failed",
            "detail": f"Driver returned: {result.status}",
        }

    except Exception as error:
        return {
            "status": "failed",
            "detail": f"{type(error).__name__}: {error}",
        }
    finally:
        if store is not None:
            store.close()
