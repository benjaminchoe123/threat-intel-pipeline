"""Minimum-interval pacing that spans a whole run.

VirusTotal's free tier is 4 requests/minute on a sliding window. The original
pacing slept only between the lookups *within* one item, so item N's last request
and item N+1's first were issued back-to-back — over the limit. The only thing
hiding it was the incidental latency of `claude -p`, which is not a rate limiter.

A limiter instance is module-level state in each client, so the interval is
honored across items and across services for the life of the process.
"""

import time


class RateLimiter:
    """Blocks until at least min_interval seconds have passed since the last call.

    sleep/clock are injectable so tests can assert pacing without real time.
    """

    def __init__(self, min_interval, sleep=time.sleep, clock=time.monotonic):
        self.min_interval = min_interval
        self._sleep = sleep
        self._clock = clock
        self._last = None

    def wait(self):
        """Call immediately before issuing a request."""
        now = self._clock()
        if self._last is not None:
            remaining = self.min_interval - (now - self._last)
            if remaining > 0:
                self._sleep(remaining)
                now = self._clock()
        self._last = now

    def reset(self):
        self._last = None
