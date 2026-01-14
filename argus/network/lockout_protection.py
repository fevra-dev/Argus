"""
Credential spray and lockout protection for Argus.

Implements intelligent rate limiting and lockout detection
to prevent account lockouts during scanning.

Based on 2025 threat research: 95% of API attacks come from
authenticated sessions - we must be careful not to trigger
defensive lockouts during testing.
"""

import time
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class LockoutPolicy:
    """
    Lockout avoidance policy configuration.
    
    Attributes:
        max_attempts_per_user: Max attempts for single username before cooldown
        max_attempts_per_host: Max total attempts per host before cooldown
        cooldown_seconds: Seconds to wait after hitting limit
        delay_between_attempts: Seconds between each attempt
        detect_lockout_messages: Strings that indicate account lockout
        abort_on_lockout: Stop testing host if lockout detected
    """
    max_attempts_per_user: int = 3
    max_attempts_per_host: int = 10
    cooldown_seconds: int = 300  # 5 minutes
    delay_between_attempts: float = 2.0
    detect_lockout_messages: List[str] = field(default_factory=lambda: [
        "account locked",
        "too many attempts",
        "temporarily blocked",
        "try again later",
        "maximum attempts exceeded",
        "account disabled",
        "login temporarily disabled",
        "rate limit exceeded",
        "access denied - too many failures",
    ])
    abort_on_lockout: bool = True


@dataclass
class AttemptTracker:
    """Tracks authentication attempts for a target."""
    host: str
    attempts: int = 0
    user_attempts: Dict[str, int] = field(default_factory=dict)
    last_attempt: Optional[datetime] = None
    lockout_detected: bool = False
    cooldown_until: Optional[datetime] = None


class LockoutProtection:
    """
    Intelligent lockout protection manager.
    
    Prevents account lockouts during credential testing by:
    - Tracking attempts per username and per host
    - Detecting lockout responses
    - Implementing cooldown periods
    - Spreading attempts across time
    
    Usage:
        protection = LockoutProtection(policy)
        
        if protection.can_attempt(host, username):
            result = test_credential(host, username, password)
            protection.record_attempt(host, username, result)
        else:
            # Skip or wait
            wait_time = protection.get_wait_time(host, username)
    """
    
    def __init__(self, policy: LockoutPolicy = None):
        """
        Initialize lockout protection.
        
        Args:
            policy: LockoutPolicy configuration (uses defaults if None)
        """
        self.policy = policy or LockoutPolicy()
        self.trackers: Dict[str, AttemptTracker] = {}
        self.global_delay = 0.0
        
        logger.info(f"LockoutProtection initialized: max {self.policy.max_attempts_per_user}/user, "
                   f"{self.policy.max_attempts_per_host}/host")
    
    def can_attempt(self, host: str, username: str) -> Tuple[bool, Optional[str]]:
        """
        Check if an attempt is safe to make.
        
        Args:
            host: Target host
            username: Username to test
            
        Returns:
            Tuple of (can_attempt, reason_if_blocked)
        """
        tracker = self._get_tracker(host)
        
        # Check if in cooldown
        if tracker.cooldown_until:
            if datetime.now() < tracker.cooldown_until:
                remaining = (tracker.cooldown_until - datetime.now()).seconds
                return False, f"Cooldown: {remaining}s remaining"
            else:
                # Cooldown expired, reset
                self._reset_tracker(host)
                tracker = self._get_tracker(host)
        
        # Check if lockout was detected
        if tracker.lockout_detected and self.policy.abort_on_lockout:
            return False, "Lockout detected - aborting"
        
        # Check per-user limit
        user_attempts = tracker.user_attempts.get(username, 0)
        if user_attempts >= self.policy.max_attempts_per_user:
            return False, f"Max attempts ({self.policy.max_attempts_per_user}) for user '{username}'"
        
        # Check per-host limit
        if tracker.attempts >= self.policy.max_attempts_per_host:
            # Enter cooldown
            tracker.cooldown_until = datetime.now() + timedelta(seconds=self.policy.cooldown_seconds)
            logger.warning(f"Host {host}: entering {self.policy.cooldown_seconds}s cooldown")
            return False, f"Max attempts ({self.policy.max_attempts_per_host}) for host - cooldown started"
        
        return True, None
    
    def record_attempt(
        self,
        host: str,
        username: str,
        success: bool,
        response_text: str = ""
    ) -> bool:
        """
        Record an authentication attempt.
        
        Args:
            host: Target host
            username: Username tested
            success: Whether authentication succeeded
            response_text: Server response for lockout detection
            
        Returns:
            True if lockout was detected
        """
        tracker = self._get_tracker(host)
        
        # Update counts
        tracker.attempts += 1
        tracker.user_attempts[username] = tracker.user_attempts.get(username, 0) + 1
        tracker.last_attempt = datetime.now()
        
        # Check for lockout indicators
        lockout_detected = self._check_lockout(response_text)
        
        if lockout_detected:
            tracker.lockout_detected = True
            logger.warning(f"LOCKOUT DETECTED on {host} for user '{username}'")
            
            if self.policy.abort_on_lockout:
                tracker.cooldown_until = datetime.now() + timedelta(seconds=self.policy.cooldown_seconds * 2)
        
        return lockout_detected
    
    def get_wait_time(self, host: str, username: str = None) -> float:
        """Get recommended wait time before next attempt."""
        tracker = self._get_tracker(host)
        
        # If in cooldown, return remaining time
        if tracker.cooldown_until:
            remaining = (tracker.cooldown_until - datetime.now()).total_seconds()
            return max(0, remaining)
        
        # Otherwise return standard delay
        return self.policy.delay_between_attempts
    
    def get_stats(self) -> Dict:
        """Get current protection statistics."""
        return {
            "hosts_tracked": len(self.trackers),
            "total_attempts": sum(t.attempts for t in self.trackers.values()),
            "lockouts_detected": sum(1 for t in self.trackers.values() if t.lockout_detected),
            "hosts_in_cooldown": sum(
                1 for t in self.trackers.values()
                if t.cooldown_until and datetime.now() < t.cooldown_until
            ),
            "hosts": {
                host: {
                    "attempts": t.attempts,
                    "lockout_detected": t.lockout_detected,
                    "in_cooldown": bool(t.cooldown_until and datetime.now() < t.cooldown_until)
                }
                for host, t in self.trackers.items()
            }
        }
    
    def wait_if_needed(self, host: str, username: str = None) -> None:
        """Block until it's safe to attempt (with rate limiting)."""
        wait_time = self.get_wait_time(host, username)
        if wait_time > 0:
            logger.debug(f"Rate limiting: waiting {wait_time:.1f}s")
            time.sleep(wait_time)
    
    def _get_tracker(self, host: str) -> AttemptTracker:
        """Get or create tracker for host."""
        if host not in self.trackers:
            self.trackers[host] = AttemptTracker(host=host)
        return self.trackers[host]
    
    def _reset_tracker(self, host: str) -> None:
        """Reset tracker for host after cooldown."""
        if host in self.trackers:
            old = self.trackers[host]
            self.trackers[host] = AttemptTracker(
                host=host,
                lockout_detected=old.lockout_detected  # Preserve lockout state
            )
    
    def _check_lockout(self, response_text: str) -> bool:
        """Check if response indicates account lockout."""
        if not response_text:
            return False
        
        response_lower = response_text.lower()
        for indicator in self.policy.detect_lockout_messages:
            if indicator.lower() in response_lower:
                return True
        
        return False


# Convenience function for quick protection
def create_safe_scanner_policy(aggressive: bool = False) -> LockoutPolicy:
    """
    Create a lockout policy based on scan aggressiveness.
    
    Args:
        aggressive: If True, use more attempts but higher risk of lockout
        
    Returns:
        Configured LockoutPolicy
    """
    if aggressive:
        return LockoutPolicy(
            max_attempts_per_user=5,
            max_attempts_per_host=20,
            cooldown_seconds=120,
            delay_between_attempts=1.0,
            abort_on_lockout=False
        )
    else:
        # Safe defaults
        return LockoutPolicy(
            max_attempts_per_user=3,
            max_attempts_per_host=10,
            cooldown_seconds=300,
            delay_between_attempts=2.0,
            abort_on_lockout=True
        )


# Module exports
__all__ = [
    'LockoutProtection',
    'LockoutPolicy',
    'AttemptTracker',
    'create_safe_scanner_policy'
]
