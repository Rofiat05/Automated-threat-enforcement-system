import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from audit_log import write_audit
from duplicate_check import AlertIdStore
from front_door import process_alert
from replay_check import NonceStore

MAX_BODY_BYTES = 10000


def status_for(decision, reason):
    if decision == "accepted":
        return 202
    if reason in ("signature is not valid",
                  "timestamp is too old or not valid"):
        return 401
    if reason in ("nonce was already used (replay)", "duplicate alert"):
        return 409
    return 400


def create_app(secret, audit_path, decide=None, apply_block=None):
    app = FastAPI()
    nonce_store = NonceStore()
    id_store = AlertIdStore()

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.post("/v1/alerts")
    async def receive_alert(request: Request):
        body = await request.body()
        now = int(time.time())

        if len(body) > MAX_BODY_BYTES:
            write_audit(audit_path, now, None, "rejected", "body is too large")
            return JSONResponse(
                status_code=413,
                content={"decision": "rejected", "reason": "body is too large"},
            )

        result = process_alert(
            body,
            request.headers.get("X-Timestamp"),
            request.headers.get("X-Nonce"),
            request.headers.get("X-Signature"),
            secret,
            nonce_store,
            id_store,
            audit_path,
            now,
            decide=decide,
            apply_block=apply_block,
        )
        return JSONResponse(
            status_code=status_for(result["decision"], result["reason"]),
            content=result,
        )

    return app


def create_app_from_env():
    secret = os.environ.get("ALERT_SECRET")
    if not secret:
        raise RuntimeError("ALERT_SECRET is not set")
    audit_path = os.environ.get("AUDIT_LOG_PATH", "audit.jsonl")

    decide = None
    apply_block = None
    mode = os.environ.get("ENFORCE_MODE", "off")
    if mode == "stub":
        # stand-in decision plus E's driver; replace decide with C's function later
        from policy_engine import decide as stub_decide
        from driver_adapter import apply_block as adapter_apply_block

        driver_audit = str(Path(audit_path).with_name("driver_audit.jsonl"))

        def apply_block(decision):
            return adapter_apply_block(decision, audit_path=driver_audit)

        decide = stub_decide
    elif mode == "merged":
        import sys

        merged_folder = str(Path(__file__).resolve().parents[1] / "cisco_driver_merged")
        if merged_folder not in sys.path:
            sys.path.insert(0, merged_folder)

        from policy_engine import decide as merged_decide
        from merged_driver_adapter import apply_block as merged_apply_block

        decide = merged_decide
        apply_block = merged_apply_block

    elif mode != "off":
        raise RuntimeError("ENFORCE_MODE must be off, stub or merged")


    app = create_app(secret.encode("utf-8"), audit_path, decide, apply_block)

    if mode == "merged":
        from cisco_driver.driver import CiscoDriver
        from cisco_driver.restconf_client import RestconfClient
        from cisco_driver.store import BlockStore
        from cisco_driver.expiry_worker import ExpiryWorker

        base_folder = Path(merged_folder)

        client = RestconfClient(
            state_path=os.environ.get(
                "MERGED_ACL_PATH",
                str(base_folder / "merged_acl_state.json")
            )
        )

        store = BlockStore(
            os.environ.get(
                "MERGED_DB_PATH",
                str(base_folder / "merged_blocks.db")
            )
        )

        driver = CiscoDriver(
            {"mock-router-1": client},
            store
        )

        @asynccontextmanager
        async def lifespan(app):
            worker = ExpiryWorker(
                driver,
                interval=2.0,
                recover=True
            )

            app.state.expiry_worker = worker
            worker.start()

            try:
                yield
            finally:
                worker.stop()
                store.close()

        app.router.lifespan_context = lifespan

    return app
