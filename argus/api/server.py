"""
Argus REST API Server - FastAPI Implementation.

Enterprise-grade API for remote scanning, automation,
and integration with security orchestration platforms.

Features:
- Async background scanning
- Real-time progress tracking
- CVE intelligence enrichment
- Swagger/OpenAPI documentation
- CORS support for web dashboards
"""

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from enum import Enum
import uuid
from datetime import datetime
import asyncio
import logging

logger = logging.getLogger(__name__)

# API metadata
app = FastAPI(
    title="Argus API",
    description="""
## Enterprise Security Scanning API

Argus - The All-Seeing Eye - provides automated default credential 
detection with real-time CVE intelligence enrichment.

### Features
- 🚀 **High-Performance Scanning** - Async I/O for 3-5x faster scans
- 🧠 **CVE Intelligence** - Real-time NVD and CISA KEV integration
- 📊 **Rich Reporting** - JSON, CSV, and HTML export formats
- 🔔 **Notifications** - Slack, Discord, Email, Teams webhooks
- 📈 **SIEM Integration** - Splunk, ELK, Syslog support

### MITRE ATT&CK Mapping
- **T1078.001**: Valid Accounts - Default Accounts
    """,
    version="0.3.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# CORS configuration for web dashboard
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage (use Redis/PostgreSQL in production)
scans_db: Dict[str, dict] = {}
schedules_db: Dict[str, dict] = {}


class ScanStatus(str, Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanRequest(BaseModel):
    """Request model for creating a new scan."""
    targets: List[str] = Field(..., description="List of targets (IPs, CIDR ranges)")
    ports: List[int] = Field(default=[22, 23, 21, 80, 443], description="Ports to scan")
    threads: int = Field(default=10, ge=1, le=50, description="Concurrent threads")
    timeout: int = Field(default=5, ge=1, le=30, description="Connection timeout (seconds)")
    enrich_cves: bool = Field(default=False, description="Enable CVE enrichment")
    check_exploits: bool = Field(default=False, description="Check for known exploits")
    nvd_api_key: Optional[str] = Field(default=None, description="NVD API key")
    
    class Config:
        json_schema_extra = {
            "example": {
                "targets": ["192.168.1.0/24"],
                "ports": [22, 80, 443],
                "threads": 10,
                "enrich_cves": True,
                "check_exploits": True
            }
        }


class ScanResponse(BaseModel):
    """Response model for scan operations."""
    scan_id: str
    status: ScanStatus
    progress: int = Field(ge=0, le=100)
    started_at: str
    completed_at: Optional[str] = None
    targets_count: int
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    error: Optional[str] = None


class ScanDetailResponse(ScanResponse):
    """Detailed scan response with findings."""
    findings: List[Dict] = []
    intelligence_report: Optional[Dict] = None
    scan_duration_ms: int = 0


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    uptime_seconds: float
    active_scans: int
    total_scans: int


# Global state
start_time = datetime.now()


def create_scan_record(scan_id: str, request: ScanRequest) -> Dict:
    """Create a new scan record in the database."""
    return {
        "scan_id": scan_id,
        "status": ScanStatus.PENDING,
        "progress": 0,
        "started_at": datetime.now().isoformat(),
        "completed_at": None,
        "targets": request.targets,
        "targets_count": len(request.targets),
        "ports": request.ports,
        "findings": [],
        "findings_count": 0,
        "critical_count": 0,
        "high_count": 0,
        "request": request.model_dump(),
        "error": None,
        "intelligence_report": None,
        "scan_duration_ms": 0
    }


async def run_scan_background(scan_id: str, request: ScanRequest):
    """Execute scan in background task."""
    scan_record = scans_db[scan_id]
    
    try:
        scan_record["status"] = ScanStatus.RUNNING
        scan_record["progress"] = 10
        
        logger.info(f"Argus starting scan {scan_id} for {len(request.targets)} targets")
        
        # Import scanner
        from ..scanner import ArgusScanner
        from ..models import ScanResult
        
        # Create scanner instance
        scanner = ArgusScanner(
            threads=request.threads,
            timeout=request.timeout,
            stop_on_success=True,
            grab_banners=True
        )
        
        scan_record["progress"] = 30
        
        # Run scan (in thread pool for sync code)
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(scanner.scan, request.targets, request.ports)
            result = future.result()
        
        scan_record["progress"] = 70
        
        # Process findings
        enriched_findings = []
        intelligence_report = None
        
        if request.enrich_cves and result.findings:
            logger.info(f"Enriching scan {scan_id} with CVE intelligence")
            
            try:
                from ..intel.intelligence_engine import IntelligenceEngine
                
                engine = IntelligenceEngine(
                    nvd_api_key=request.nvd_api_key,
                    enable_exploit_check=request.check_exploits
                )
                
                for finding in result.findings:
                    banner = getattr(finding, 'banner', '')
                    intel = engine.analyze_finding(finding, banner)
                    
                    enriched_findings.append({
                        'finding': {
                            'host': finding.host,
                            'port': finding.port,
                            'service': finding.service.value,
                            'username': finding.username,
                            'password': finding.password,
                            'severity': finding.severity.value,
                            'access_level': finding.access_level
                        },
                        'intelligence': intel.to_dict()
                    })
                
                intelligence_report = engine.generate_intelligence_report(enriched_findings)
                
            except Exception as e:
                logger.error(f"Intelligence enrichment failed: {e}")
        else:
            # Basic findings without enrichment
            enriched_findings = [
                {
                    'finding': {
                        'host': f.host,
                        'port': f.port,
                        'service': f.service.value,
                        'username': f.username,
                        'password': f.password,
                        'severity': f.severity.value,
                        'access_level': f.access_level
                    }
                }
                for f in result.findings
            ]
        
        scan_record["progress"] = 90
        
        # Update record with results
        scan_record["status"] = ScanStatus.COMPLETED
        scan_record["progress"] = 100
        scan_record["completed_at"] = datetime.now().isoformat()
        scan_record["findings"] = enriched_findings
        scan_record["findings_count"] = result.total_findings
        scan_record["critical_count"] = result.critical_count
        scan_record["high_count"] = result.high_count
        scan_record["scan_duration_ms"] = result.scan_duration_ms
        scan_record["intelligence_report"] = intelligence_report
        
        logger.info(
            f"Argus scan {scan_id} completed: {result.total_findings} findings "
            f"({result.critical_count} critical)"
        )
        
    except Exception as e:
        logger.error(f"Argus scan {scan_id} failed: {e}")
        scan_record["status"] = ScanStatus.FAILED
        scan_record["completed_at"] = datetime.now().isoformat()
        scan_record["error"] = str(e)


# API Endpoints

@app.get("/", tags=["General"])
async def root():
    """API root - service information."""
    return {
        "service": "Argus API",
        "version": "0.2.0",
        "description": "The All-Seeing Eye - Enterprise Security Scanning Platform",
        "docs": "/api/docs",
        "health": "/api/health"
    }


@app.get("/api/health", response_model=HealthResponse, tags=["General"])
async def health_check():
    """Health check endpoint for monitoring."""
    uptime = (datetime.now() - start_time).total_seconds()
    active = sum(1 for s in scans_db.values() if s["status"] == ScanStatus.RUNNING)
    
    return HealthResponse(
        status="healthy",
        version="0.3.0",
        uptime_seconds=uptime,
        active_scans=active,
        total_scans=len(scans_db)
    )


@app.post("/api/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """
    Create and start a new security scan.
    
    The scan runs asynchronously in the background. Use the returned
    scan_id to check status and retrieve results.
    """
    scan_id = str(uuid.uuid4())
    
    # Create scan record
    scan_record = create_scan_record(scan_id, request)
    scans_db[scan_id] = scan_record
    
    # Start scan in background
    background_tasks.add_task(run_scan_background, scan_id, request)
    
    logger.info(f"Argus created scan {scan_id}")
    
    return ScanResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        progress=0,
        started_at=scan_record["started_at"],
        targets_count=len(request.targets)
    )


@app.get("/api/scans", tags=["Scans"])
async def list_scans(
    status: Optional[ScanStatus] = Query(None, description="Filter by status"),
    limit: int = Query(50, ge=1, le=500, description="Max results"),
    offset: int = Query(0, ge=0, description="Results offset")
):
    """List all scans with optional filtering and pagination."""
    scans = list(scans_db.values())
    
    # Filter by status
    if status:
        scans = [s for s in scans if s["status"] == status]
    
    # Sort by started_at (newest first)
    scans.sort(key=lambda x: x["started_at"], reverse=True)
    
    # Paginate
    total = len(scans)
    scans = scans[offset:offset + limit]
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "scans": [
            ScanResponse(
                scan_id=s["scan_id"],
                status=s["status"],
                progress=s["progress"],
                started_at=s["started_at"],
                completed_at=s.get("completed_at"),
                targets_count=s["targets_count"],
                findings_count=s.get("findings_count", 0),
                critical_count=s.get("critical_count", 0),
                high_count=s.get("high_count", 0),
                error=s.get("error")
            )
            for s in scans
        ]
    }


@app.get("/api/scans/{scan_id}", response_model=ScanDetailResponse, tags=["Scans"])
async def get_scan(scan_id: str):
    """Get detailed scan results including findings."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans_db[scan_id]
    
    return ScanDetailResponse(
        scan_id=scan["scan_id"],
        status=scan["status"],
        progress=scan["progress"],
        started_at=scan["started_at"],
        completed_at=scan.get("completed_at"),
        targets_count=scan["targets_count"],
        findings_count=scan.get("findings_count", 0),
        critical_count=scan.get("critical_count", 0),
        high_count=scan.get("high_count", 0),
        findings=scan.get("findings", []),
        intelligence_report=scan.get("intelligence_report"),
        scan_duration_ms=scan.get("scan_duration_ms", 0),
        error=scan.get("error")
    )


@app.delete("/api/scans/{scan_id}", tags=["Scans"])
async def delete_scan(scan_id: str):
    """Delete a scan and its results."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans_db[scan_id]
    
    if scan["status"] == ScanStatus.RUNNING:
        raise HTTPException(
            status_code=400,
            detail="Cannot delete running scan. Cancel it first."
        )
    
    del scans_db[scan_id]
    
    return {"message": "Scan deleted", "scan_id": scan_id}


@app.post("/api/scans/{scan_id}/cancel", tags=["Scans"])
async def cancel_scan(scan_id: str):
    """Cancel a running or pending scan."""
    if scan_id not in scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = scans_db[scan_id]
    
    if scan["status"] not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel scan with status: {scan['status']}"
        )
    
    scan["status"] = ScanStatus.CANCELLED
    scan["completed_at"] = datetime.now().isoformat()
    
    return {"message": "Scan cancelled", "scan_id": scan_id}


@app.get("/api/stats", tags=["Statistics"])
async def get_statistics():
    """Get overall scanning statistics and metrics."""
    total_scans = len(scans_db)
    completed = sum(1 for s in scans_db.values() if s["status"] == ScanStatus.COMPLETED)
    failed = sum(1 for s in scans_db.values() if s["status"] == ScanStatus.FAILED)
    running = sum(1 for s in scans_db.values() if s["status"] == ScanStatus.RUNNING)
    
    total_findings = sum(s.get("findings_count", 0) for s in scans_db.values())
    critical_findings = sum(s.get("critical_count", 0) for s in scans_db.values())
    high_findings = sum(s.get("high_count", 0) for s in scans_db.values())
    
    return {
        "scans": {
            "total": total_scans,
            "completed": completed,
            "failed": failed,
            "running": running
        },
        "findings": {
            "total": total_findings,
            "critical": critical_findings,
            "high": high_findings,
            "average_per_scan": round(total_findings / completed, 2) if completed > 0 else 0
        },
        "uptime_seconds": (datetime.now() - start_time).total_seconds()
    }


# Run with: uvicorn argus.api.server:app --reload --port 8000
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
