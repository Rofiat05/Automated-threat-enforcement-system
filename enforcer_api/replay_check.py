class NonceStore:
    def __init__(self, keep_seconds=120):
        self.keep_seconds = keep_seconds
        self.seen = {}

    def is_replay(self, nonce, now):
        # forget nonces that are too old to matter
        too_old = [n for n, t in self.seen.items() if now - t > self.keep_seconds]
        for n in too_old:
            del self.seen[n]

        if nonce in self.seen:
            return True
        self.seen[nonce] = now
        return False