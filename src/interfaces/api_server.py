"""REST API server for BlueGuardian AI.

This module provides a FastAPI-based REST API for submitting analyses,
querying results, and managing the BlueGuardian AI system.
"""

import asyncio
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import uvicorn
from fastapi import (
    FastAPI,
    File,
    HTTPException,
    UploadFile,
    BackgroundTasks,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from loguru import logger
from pydantic import BaseModel, Field

from src.agents.base_agent import AnalysisResult, AnalysisStatus, Verdict
from src.config.settings import Settings, get_settings
from src.core.orchestrator import Orchestrator


# Pydantic models for API
class AnalysisRequest(BaseModel):
    """Request to analyze an artifact."""

    artifact_path: Optional[str] = None
    agent_type: Optional[str] = None
    options: Dict[str, Any] = Field(default_factory=dict)


class JobResponse(BaseModel):
    """Response containing job information."""

    job_id: str
    status: str
    agent_type: str
    artifact_name: str
    created_at: str
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None


class AnalysisResultResponse(BaseModel):
    """Response containing analysis results."""

    job_id: str
    status: str
    verdict: str
    confidence: float
    summary: str
    agent_name: str
    artifact_name: str
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    iocs: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)


class AgentInfo(BaseModel):
    """Information about an agent."""

    name: str
    description: str
    supported_file_types: List[str]
    enabled: bool


class SystemStatusResponse(BaseModel):
    """System status information."""

    version: str
    agents_available: int
    ai_providers: List[str]
    consensus_enabled: bool
    hallucination_guard_enabled: bool
    threat_intel_enabled: Dict[str, bool]


class APIServer:
    """FastAPI server for BlueGuardian AI."""

    def __init__(self, settings: Optional[Settings] = None):
        """Initialize API server.

        Args:
            settings: Application settings
        """
        self.settings = settings or get_settings()
        self.orchestrator: Optional[Orchestrator] = None
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.upload_dir = Path("uploads")
        self.upload_dir.mkdir(exist_ok=True)

        # Create FastAPI app
        self.app = FastAPI(
            title="BlueGuardian AI API",
            description="REST API for AI-powered security analysis",
            version="1.0.0",
            docs_url="/api/docs",
            redoc_url="/api/redoc",
        )

        # Add CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],  # Configure appropriately for production
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

        # Register routes
        self._register_routes()

        logger.info("Initialized APIServer")

    def _register_routes(self) -> None:
        """Register API routes."""

        @self.app.on_event("startup")
        async def startup_event():
            """Initialize orchestrator on startup."""
            logger.info("Starting API server...")
            self.orchestrator = Orchestrator(self.settings)

        @self.app.on_event("shutdown")
        async def shutdown_event():
            """Cleanup on shutdown."""
            logger.info("Shutting down API server...")
            if self.orchestrator:
                await self.orchestrator.shutdown()

        @self.app.get("/api/v1/health")
        async def health_check():
            """Health check endpoint."""
            return {"status": "healthy", "timestamp": datetime.now().isoformat()}

        @self.app.get("/api/v1/status", response_model=SystemStatusResponse)
        async def get_status():
            """Get system status."""
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="System not ready")

            status_info = self.orchestrator.get_status()

            return SystemStatusResponse(
                version="1.0.0",
                agents_available=status_info['agents']['count'],
                ai_providers=[p.value for p in status_info['providers']['models']],
                consensus_enabled=status_info['consensus']['enabled'],
                hallucination_guard_enabled=status_info['hallucination_guard']['enabled'],
                threat_intel_enabled={
                    'virustotal': status_info['threat_intel']['virustotal'],
                },
            )

        @self.app.get("/api/v1/agents", response_model=List[AgentInfo])
        async def list_agents():
            """List available agents."""
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="System not ready")

            agents_info = []
            for agent_name, agent in self.orchestrator.agents.items():
                agents_info.append(AgentInfo(
                    name=agent_name,
                    description=agent.__class__.__doc__ or "",
                    supported_file_types=agent.get_supported_file_types(),
                    enabled=True,
                ))

            return agents_info

        @self.app.post("/api/v1/analyze/file", response_model=JobResponse)
        async def analyze_file(
            background_tasks: BackgroundTasks,
            file: UploadFile = File(...),
            agent_type: Optional[str] = None,
        ):
            """Submit a file for analysis."""
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="System not ready")

            # Generate job ID
            job_id = str(uuid.uuid4())

            # Save uploaded file
            file_path = self.upload_dir / f"{job_id}_{file.filename}"
            with open(file_path, "wb") as f:
                content = await file.read()
                f.write(content)

            # Create job
            job = {
                'job_id': job_id,
                'status': 'pending',
                'agent_type': agent_type or 'auto',
                'artifact_name': file.filename,
                'artifact_path': str(file_path),
                'created_at': datetime.now().isoformat(),
                'result': None,
            }
            self.jobs[job_id] = job

            # Schedule analysis in background
            background_tasks.add_task(self._run_analysis, job_id, str(file_path), agent_type)

            logger.info(f"Created analysis job: {job_id} for {file.filename}")

            return JobResponse(
                job_id=job_id,
                status='pending',
                agent_type=agent_type or 'auto',
                artifact_name=file.filename,
                created_at=job['created_at'],
            )

        @self.app.post("/api/v1/analyze/url", response_model=JobResponse)
        async def analyze_url(
            background_tasks: BackgroundTasks,
            request: AnalysisRequest,
        ):
            """Analyze a URL or network indicator."""
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="System not ready")

            if not request.artifact_path:
                raise HTTPException(status_code=400, detail="artifact_path is required")

            # Generate job ID
            job_id = str(uuid.uuid4())

            # Create job
            job = {
                'job_id': job_id,
                'status': 'pending',
                'agent_type': request.agent_type or 'network',
                'artifact_name': request.artifact_path,
                'artifact_path': request.artifact_path,
                'created_at': datetime.now().isoformat(),
                'result': None,
                'options': request.options,
            }
            self.jobs[job_id] = job

            # Schedule analysis in background
            background_tasks.add_task(
                self._run_analysis,
                job_id,
                request.artifact_path,
                request.agent_type,
                request.options,
            )

            logger.info(f"Created analysis job: {job_id} for {request.artifact_path}")

            return JobResponse(
                job_id=job_id,
                status='pending',
                agent_type=request.agent_type or 'network',
                artifact_name=request.artifact_path,
                created_at=job['created_at'],
            )

        @self.app.get("/api/v1/jobs/{job_id}", response_model=JobResponse)
        async def get_job_status(job_id: str):
            """Get job status."""
            if job_id not in self.jobs:
                raise HTTPException(status_code=404, detail="Job not found")

            job = self.jobs[job_id]

            return JobResponse(
                job_id=job_id,
                status=job['status'],
                agent_type=job['agent_type'],
                artifact_name=job['artifact_name'],
                created_at=job['created_at'],
                completed_at=job.get('completed_at'),
                duration_seconds=job.get('duration_seconds'),
            )

        @self.app.get("/api/v1/jobs/{job_id}/result", response_model=AnalysisResultResponse)
        async def get_job_result(job_id: str):
            """Get analysis result."""
            if job_id not in self.jobs:
                raise HTTPException(status_code=404, detail="Job not found")

            job = self.jobs[job_id]

            if job['status'] not in ['completed', 'failed']:
                raise HTTPException(status_code=202, detail="Analysis still in progress")

            if not job['result']:
                raise HTTPException(status_code=500, detail="No result available")

            result: AnalysisResult = job['result']

            # Convert IOCs to dict
            iocs_dict = [
                {
                    'type': ioc.type,
                    'value': ioc.value,
                    'confidence': ioc.confidence,
                    'description': ioc.description,
                }
                for ioc in result.iocs
            ]

            return AnalysisResultResponse(
                job_id=job_id,
                status=job['status'],
                verdict=result.verdict.value,
                confidence=result.confidence,
                summary=result.summary,
                agent_name=result.agent_name,
                artifact_name=result.artifact_name,
                started_at=result.started_at.isoformat(),
                completed_at=result.completed_at.isoformat() if result.completed_at else None,
                duration_seconds=result.duration_seconds,
                iocs=iocs_dict,
                mitre_techniques=result.mitre_techniques,
                tags=result.tags,
                warnings=result.warnings,
                errors=result.errors,
            )

        @self.app.get("/api/v1/jobs")
        async def list_jobs(
            status: Optional[str] = None,
            limit: int = 100,
        ):
            """List all jobs."""
            jobs_list = list(self.jobs.values())

            # Filter by status if provided
            if status:
                jobs_list = [j for j in jobs_list if j['status'] == status]

            # Sort by created_at descending
            jobs_list.sort(key=lambda x: x['created_at'], reverse=True)

            # Limit results
            jobs_list = jobs_list[:limit]

            return [
                JobResponse(
                    job_id=j['job_id'],
                    status=j['status'],
                    agent_type=j['agent_type'],
                    artifact_name=j['artifact_name'],
                    created_at=j['created_at'],
                    completed_at=j.get('completed_at'),
                    duration_seconds=j.get('duration_seconds'),
                )
                for j in jobs_list
            ]

        @self.app.delete("/api/v1/jobs/{job_id}")
        async def delete_job(job_id: str):
            """Delete a job."""
            if job_id not in self.jobs:
                raise HTTPException(status_code=404, detail="Job not found")

            # Remove uploaded file if exists
            job = self.jobs[job_id]
            if 'artifact_path' in job:
                artifact_path = Path(job['artifact_path'])
                if artifact_path.exists() and artifact_path.parent == self.upload_dir:
                    artifact_path.unlink()

            # Remove job
            del self.jobs[job_id]

            return {"message": "Job deleted successfully"}

        @self.app.get("/api/v1/jobs/{job_id}/report/{format}")
        async def download_report(job_id: str, format: str):
            """Download report in specified format."""
            if job_id not in self.jobs:
                raise HTTPException(status_code=404, detail="Job not found")

            job = self.jobs[job_id]

            if job['status'] != 'completed':
                raise HTTPException(status_code=400, detail="Analysis not completed")

            if format not in ['json', 'html', 'pdf']:
                raise HTTPException(status_code=400, detail="Unsupported format")

            # Generate report (will be implemented in report generator)
            # For now, return JSON
            if format == 'json':
                result: AnalysisResult = job['result']
                return JSONResponse(content={
                    'job_id': job_id,
                    'verdict': result.verdict.value,
                    'confidence': result.confidence,
                    'summary': result.summary,
                    'artifact_name': result.artifact_name,
                    'agent_name': result.agent_name,
                    'iocs': [
                        {'type': ioc.type, 'value': ioc.value, 'confidence': ioc.confidence}
                        for ioc in result.iocs
                    ],
                    'mitre_techniques': result.mitre_techniques,
                    'tags': result.tags,
                })

            raise HTTPException(status_code=501, detail=f"Format {format} not yet implemented")

        @self.app.get("/api/v1/costs")
        async def get_costs():
            """Get API costs."""
            if not self.orchestrator:
                raise HTTPException(status_code=503, detail="System not ready")

            costs = self.orchestrator.get_costs()
            return costs

    async def _run_analysis(
        self,
        job_id: str,
        artifact_path: str,
        agent_type: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Run analysis in background.

        Args:
            job_id: Job ID
            artifact_path: Path to artifact
            agent_type: Agent type to use
            options: Additional options
        """
        try:
            # Update job status
            self.jobs[job_id]['status'] = 'running'

            # Run analysis
            logger.info(f"Running analysis for job {job_id}")
            result = await self.orchestrator.analyze_file(
                artifact_path,
                agent_type=agent_type,
                **(options or {}),
            )

            # Update job with result
            self.jobs[job_id]['status'] = 'completed'
            self.jobs[job_id]['result'] = result
            self.jobs[job_id]['completed_at'] = datetime.now().isoformat()
            self.jobs[job_id]['duration_seconds'] = result.duration_seconds

            logger.info(f"Analysis complete for job {job_id}: {result.verdict.value}")

        except Exception as e:
            logger.error(f"Analysis failed for job {job_id}: {e}", exc_info=True)
            self.jobs[job_id]['status'] = 'failed'
            self.jobs[job_id]['error'] = str(e)
            self.jobs[job_id]['completed_at'] = datetime.now().isoformat()

    def run(self, host: str = "0.0.0.0", port: int = 8000):
        """Run the API server.

        Args:
            host: Host to bind to
            port: Port to bind to
        """
        logger.info(f"Starting API server on {host}:{port}")
        uvicorn.run(self.app, host=host, port=port, log_level="info")


def create_app() -> FastAPI:
    """Create FastAPI app instance.

    Returns:
        FastAPI application
    """
    server = APIServer()
    return server.app


# Create global app instance for uvicorn
app = create_app()


if __name__ == "__main__":
    # Run server
    server = APIServer()
    server.run()
