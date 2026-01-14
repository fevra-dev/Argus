"""
Scan scheduler for Argus.

Enables automated recurring scans with cron-like scheduling,
job persistence, and notification integration.
"""

import uuid
from typing import List, Dict, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    from apscheduler.triggers.interval import IntervalTrigger
    HAS_APSCHEDULER = True
except ImportError:
    HAS_APSCHEDULER = False
    logger.warning("APScheduler not installed. Scheduling disabled.")


@dataclass
class ScheduledScan:
    """
    Scheduled scan configuration.
    
    Attributes:
        job_id: Unique job identifier
        name: Human-readable job name
        targets: List of scan targets
        ports: List of ports to scan
        cron_expression: Cron schedule (e.g., "0 2 * * *" for 2 AM daily)
        interval_hours: Alternative: run every N hours
        enabled: Whether the job is active
        notify_on_complete: Send notifications after scan
        created_at: Job creation timestamp
        last_run: Last execution timestamp
        next_run: Next scheduled execution
    """
    job_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "Scheduled Scan"
    targets: List[str] = field(default_factory=list)
    ports: List[int] = field(default_factory=lambda: [22, 23, 21, 80, 443])
    cron_expression: Optional[str] = None
    interval_hours: Optional[int] = None
    enabled: bool = True
    notify_on_complete: bool = True
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    last_run: Optional[str] = None
    next_run: Optional[str] = None


class ScanScheduler:
    """
    Background scan scheduler.
    
    Manages scheduled scan jobs with persistence,
    cron/interval triggers, and callback support.
    
    Usage:
        scheduler = ScanScheduler()
        scheduler.start()
        
        job = ScheduledScan(
            name="Nightly Network Scan",
            targets=["192.168.1.0/24"],
            cron_expression="0 2 * * *"
        )
        scheduler.add_job(job, scan_callback)
    """
    
    def __init__(self):
        """Initialize the scan scheduler."""
        self.jobs: Dict[str, ScheduledScan] = {}
        self.callbacks: Dict[str, Callable] = {}
        
        if HAS_APSCHEDULER:
            self.scheduler = BackgroundScheduler()
            self._started = False
        else:
            self.scheduler = None
            self._started = False
        
        logger.info("ScanScheduler initialized")
    
    def start(self) -> bool:
        """
        Start the background scheduler.
        
        Returns:
            True if started successfully
        """
        if not HAS_APSCHEDULER:
            logger.error("APScheduler not available")
            return False
        
        if not self._started:
            self.scheduler.start()
            self._started = True
            logger.info("Scheduler started")
        
        return True
    
    def stop(self) -> None:
        """Stop the background scheduler."""
        if self._started and self.scheduler:
            self.scheduler.shutdown()
            self._started = False
            logger.info("Scheduler stopped")
    
    def add_job(
        self,
        scheduled_scan: ScheduledScan,
        callback: Callable = None
    ) -> bool:
        """
        Add a scheduled scan job.
        
        Args:
            scheduled_scan: ScheduledScan configuration
            callback: Function to call with (targets, ports) when triggered
            
        Returns:
            True if job added successfully
        """
        if not HAS_APSCHEDULER or not self.scheduler:
            logger.error("Scheduler not available")
            return False
        
        job_id = scheduled_scan.job_id
        
        # Create trigger
        if scheduled_scan.cron_expression:
            trigger = CronTrigger.from_crontab(scheduled_scan.cron_expression)
        elif scheduled_scan.interval_hours:
            trigger = IntervalTrigger(hours=scheduled_scan.interval_hours)
        else:
            logger.error(f"Job {job_id}: No schedule specified")
            return False
        
        # Store job config
        self.jobs[job_id] = scheduled_scan
        if callback:
            self.callbacks[job_id] = callback
        
        # Add to scheduler
        self.scheduler.add_job(
            func=self._execute_job,
            trigger=trigger,
            args=[job_id],
            id=job_id,
            name=scheduled_scan.name,
            replace_existing=True
        )
        
        # Update next run time
        job = self.scheduler.get_job(job_id)
        if job:
            scheduled_scan.next_run = str(job.next_run_time)
        
        logger.info(f"Scheduled job '{scheduled_scan.name}' ({job_id[:8]})")
        return True
    
    def remove_job(self, job_id: str) -> bool:
        """
        Remove a scheduled job.
        
        Args:
            job_id: Job ID to remove
            
        Returns:
            True if removed successfully
        """
        if not self.scheduler:
            return False
        
        try:
            self.scheduler.remove_job(job_id)
            self.jobs.pop(job_id, None)
            self.callbacks.pop(job_id, None)
            logger.info(f"Removed job {job_id[:8]}")
            return True
        except Exception as e:
            logger.error(f"Failed to remove job: {e}")
            return False
    
    def pause_job(self, job_id: str) -> bool:
        """Pause a scheduled job."""
        if not self.scheduler:
            return False
        
        try:
            self.scheduler.pause_job(job_id)
            if job_id in self.jobs:
                self.jobs[job_id].enabled = False
            logger.info(f"Paused job {job_id[:8]}")
            return True
        except Exception as e:
            logger.error(f"Failed to pause job: {e}")
            return False
    
    def resume_job(self, job_id: str) -> bool:
        """Resume a paused job."""
        if not self.scheduler:
            return False
        
        try:
            self.scheduler.resume_job(job_id)
            if job_id in self.jobs:
                self.jobs[job_id].enabled = True
            logger.info(f"Resumed job {job_id[:8]}")
            return True
        except Exception as e:
            logger.error(f"Failed to resume job: {e}")
            return False
    
    def list_jobs(self) -> List[Dict]:
        """
        List all scheduled jobs.
        
        Returns:
            List of job details
        """
        jobs = []
        
        for job_id, config in self.jobs.items():
            # Update next run time
            if self.scheduler:
                sched_job = self.scheduler.get_job(job_id)
                if sched_job:
                    config.next_run = str(sched_job.next_run_time)
            
            jobs.append({
                "job_id": config.job_id,
                "name": config.name,
                "targets": config.targets,
                "ports": config.ports,
                "cron": config.cron_expression,
                "interval_hours": config.interval_hours,
                "enabled": config.enabled,
                "last_run": config.last_run,
                "next_run": config.next_run
            })
        
        return jobs
    
    def _execute_job(self, job_id: str) -> None:
        """Execute a scheduled scan job."""
        config = self.jobs.get(job_id)
        
        if not config:
            logger.error(f"Job {job_id} not found")
            return
        
        if not config.enabled:
            logger.info(f"Job {job_id[:8]} is disabled, skipping")
            return
        
        logger.info(f"Executing scheduled job: {config.name} ({job_id[:8]})")
        
        # Update last run time
        config.last_run = datetime.utcnow().isoformat()
        
        # Execute callback if registered
        callback = self.callbacks.get(job_id)
        if callback:
            try:
                callback(config.targets, config.ports)
            except Exception as e:
                logger.error(f"Job execution failed: {e}")
        else:
            logger.warning(f"No callback registered for job {job_id[:8]}")
    
    def run_now(self, job_id: str) -> bool:
        """
        Immediately execute a scheduled job.
        
        Args:
            job_id: Job ID to execute
            
        Returns:
            True if executed successfully
        """
        config = self.jobs.get(job_id)
        if not config:
            logger.error(f"Job {job_id} not found")
            return False
        
        self._execute_job(job_id)
        return True


# Module self-test
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    
    print("ScanScheduler module loaded")
    print(f"APScheduler available: {HAS_APSCHEDULER}")
    
    if HAS_APSCHEDULER:
        scheduler = ScanScheduler()
        scheduler.start()
        print("Scheduler running...")
