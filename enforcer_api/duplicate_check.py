class AlertIdStore:
    def __init__(self, keep_seconds=3600):
        self.keep_seconds = keep_seconds
        self.seen = {}

    def is_duplicate(self, alert_id, now):
        # forget alert IDs that are too old to matter
        too_old = [a for a, t in self.seen.items() if now - t > self.keep_seconds]
        for a in too_old:
            del self.seen[a]

        if alert_id in self.seen:
            return True
        self.seen[alert_id] = now
        return False
        