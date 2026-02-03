import time
from collections import defaultdict
from typing import Dict, Tuple

class RateLimiter:
    """
    Simple in-memory rate limiter using a sliding window or fixed window approach.
    """
    def __init__(self, limit: int = 100, window: int = 60):
        """
        :param limit: Number of requests allowed
        :param window: Time window in seconds
        """
        self.limit = limit
        self.window = window
        # Storage: {key: [timestamp1, timestamp2, ...]}
        self.requests: Dict[str, list] = defaultdict(list)

    def is_allowed(self, key: str) -> bool:
        """
        Check if the request is allowed for the given key (IP or API Key).
        """
        now = time.time()
        self.cleanup(key, now)
        
        if len(self.requests[key]) < self.limit:
            self.requests[key].append(now)
            return True
        return False

    def cleanup(self, key: str, now: float):
        """
        Remove old requests outside the window.
        """
        cutoff = now - self.window
        self.requests[key] = [t for t in self.requests[key] if t > cutoff]

    def get_remaining(self, key: str) -> int:
        now = time.time()
        self.cleanup(key, now)
        return max(0, self.limit - len(self.requests[key]))

    def reset(self, key: str):
        if key in self.requests:
            del self.requests[key]
