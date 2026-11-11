import os
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from audit_log import write_audit
from duplicate_check import AlertIdStore
from gatekeeper import handle_alert
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


def create_app(secret, audit_path):
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

        decision, reason = handle_alert(
            body,
            request.headers.get("X-Timestamp"),
            request.headers.get("X-Nonce"),
            request.headers.get("X-Signature"),
            secret,
            nonce_store,
            id_store,
            audit_path,
            now,
        )
        return JSONResponse(
            status_code=status_for(decision, reason),
            content={"decision": decision, "reason": reason},
        )

    return app


def create_app_from_env():
    secret = os.environ.get("ALERT_SECRET")
    if not secret:
        raise RuntimeError("ALERT_SECRET is not set")
    audit_path = os.environ.get("AUDIT_LOG_PATH", "audit.jsonl")
    return create_app(secret.encode("utf-8"), audit_path)