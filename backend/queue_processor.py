"""
Queue-based Near-Real-Time Processing
Handles domain processing in batches with polling endpoints for status updates
"""

import logging
import time
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import queue
import uuid

from celery import Celery
from celery.result import AsyncResult
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

class ProcessingStatus(Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

@dataclass
class ProcessingJob:
    """Represents a domain processing job"""
    job_id: str
    domain: str
    cse_domain: str
    status: ProcessingStatus
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    result_data: Optional[Dict[str, Any]] = None
    priority: int = 1  # 1=high, 2=medium, 3=low

class QueueProcessor:
    """Manages domain processing queue with near-real-time updates"""
    
    def __init__(self, db_session: Session):
        self.db = db_session
        self.job_queue = queue.PriorityQueue()
        self.jobs: Dict[str, ProcessingJob] = {}
        self.processing_threads = []
        self.max_workers = 3
        self.batch_size = 10
        self.polling_interval = 2  # seconds
        self.is_running = False
        self.lock = threading.Lock()
        
        # Initialize Celery for background processing
        self.celery_app = Celery('phishing_processor')
        self.celery_app.config_from_object('backend.celery_config')
        
        # Register Celery tasks
        self._register_celery_tasks()
    
    def _register_celery_tasks(self):
        """Register Celery tasks for background processing"""
        
        @self.celery_app.task(bind=True)
        def process_domain_batch(self, job_ids: List[str]):
            """Process a batch of domains"""
            try:
                logger.info(f"Processing batch of {len(job_ids)} domains")
                results = []
                
                for job_id in job_ids:
                    with self.lock:
                        job = self.jobs.get(job_id)
                        if not job:
                            continue
                        
                        job.status = ProcessingStatus.PROCESSING
                        job.started_at = datetime.now()
                
                # Import here to avoid circular imports
                from backend.detector import PhishingDetector
                from backend.intelligence import IntelligenceGatherer
                
                detector = PhishingDetector()
                intelligence = IntelligenceGatherer()
                
                for job_id in job_ids:
                    with self.lock:
                        job = self.jobs.get(job_id)
                        if not job:
                            continue
                    
                    try:
                        # Perform detection analysis
                        analysis_result = detector.analyze_domain(
                            job.domain, 
                            job.cse_domain
                        )
                        
                        # Gather intelligence
                        ti_data = intelligence.check_domain_in_feeds(job.domain)
                        
                        # Combine results
                        result_data = {
                            'analysis': analysis_result,
                            'threat_intelligence': asdict(ti_data),
                            'processing_time': (datetime.now() - job.started_at).total_seconds()
                        }
                        
                        with self.lock:
                            job.status = ProcessingStatus.COMPLETED
                            job.completed_at = datetime.now()
                            job.result_data = result_data
                        
                        results.append({
                            'job_id': job_id,
                            'status': 'completed',
                            'result': result_data
                        })
                        
                    except Exception as e:
                        logger.error(f"Failed to process domain {job.domain}: {e}")
                        with self.lock:
                            job.status = ProcessingStatus.FAILED
                            job.completed_at = datetime.now()
                            job.error_message = str(e)
                        
                        results.append({
                            'job_id': job_id,
                            'status': 'failed',
                            'error': str(e)
                        })
                
                logger.info(f"Completed batch processing: {len(results)} results")
                return results
                
            except Exception as e:
                logger.error(f"Batch processing failed: {e}")
                return []
        
        self.process_domain_batch = process_domain_batch
    
    def add_domain_job(self, domain: str, cse_domain: str, priority: int = 1) -> str:
        """Add a domain to the processing queue"""
        job_id = str(uuid.uuid4())
        job = ProcessingJob(
            job_id=job_id,
            domain=domain,
            cse_domain=cse_domain,
            status=ProcessingStatus.PENDING,
            created_at=datetime.now(),
            priority=priority
        )
        
        with self.lock:
            self.jobs[job_id] = job
            self.job_queue.put((priority, job_id))
        
        logger.info(f"Added domain {domain} to queue with job ID {job_id}")
        return job_id
    
    def add_batch_jobs(self, domains: List[Dict[str, str]], priority: int = 1) -> List[str]:
        """Add multiple domains to the processing queue"""
        job_ids = []
        for domain_data in domains:
            domain = domain_data.get('domain')
            cse_domain = domain_data.get('cse_domain', '')
            if domain:
                job_id = self.add_domain_job(domain, cse_domain, priority)
                job_ids.append(job_id)
        return job_ids
    
    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific job"""
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return None
            
            return {
                'job_id': job.job_id,
                'domain': job.domain,
                'cse_domain': job.cse_domain,
                'status': job.status.value,
                'created_at': job.created_at.isoformat(),
                'started_at': job.started_at.isoformat() if job.started_at else None,
                'completed_at': job.completed_at.isoformat() if job.completed_at else None,
                'error_message': job.error_message,
                'result_data': job.result_data
            }
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get overall queue status"""
        with self.lock:
            total_jobs = len(self.jobs)
            pending_jobs = sum(1 for job in self.jobs.values() if job.status == ProcessingStatus.PENDING)
            processing_jobs = sum(1 for job in self.jobs.values() if job.status == ProcessingStatus.PROCESSING)
            completed_jobs = sum(1 for job in self.jobs.values() if job.status == ProcessingStatus.COMPLETED)
            failed_jobs = sum(1 for job in self.jobs.values() if job.status == ProcessingStatus.FAILED)
            
            return {
                'total_jobs': total_jobs,
                'pending_jobs': pending_jobs,
                'processing_jobs': processing_jobs,
                'completed_jobs': completed_jobs,
                'failed_jobs': failed_jobs,
                'queue_size': self.job_queue.qsize(),
                'is_running': self.is_running,
                'max_workers': self.max_workers,
                'batch_size': self.batch_size
            }
    
    def get_recent_jobs(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent jobs with their status"""
        with self.lock:
            sorted_jobs = sorted(
                self.jobs.values(),
                key=lambda x: x.created_at,
                reverse=True
            )
            
            return [
                {
                    'job_id': job.job_id,
                    'domain': job.domain,
                    'cse_domain': job.cse_domain,
                    'status': job.status.value,
                    'created_at': job.created_at.isoformat(),
                    'completed_at': job.completed_at.isoformat() if job.completed_at else None,
                    'error_message': job.error_message
                }
                for job in sorted_jobs[:limit]
            ]
    
    def start_processing(self):
        """Start the queue processing"""
        if self.is_running:
            logger.warning("Queue processing is already running")
            return
        
        self.is_running = True
        logger.info("Starting queue processing...")
        
        # Start processing threads
        for i in range(self.max_workers):
            thread = threading.Thread(
                target=self._processing_worker,
                name=f"QueueWorker-{i+1}"
            )
            thread.daemon = True
            thread.start()
            self.processing_threads.append(thread)
        
        logger.info(f"Started {self.max_workers} processing workers")
    
    def stop_processing(self):
        """Stop the queue processing"""
        if not self.is_running:
            logger.warning("Queue processing is not running")
            return
        
        self.is_running = False
        logger.info("Stopping queue processing...")
        
        # Wait for threads to finish
        for thread in self.processing_threads:
            thread.join(timeout=5)
        
        self.processing_threads.clear()
        logger.info("Queue processing stopped")
    
    def _processing_worker(self):
        """Worker thread that processes jobs from the queue"""
        while self.is_running:
            try:
                # Get batch of jobs
                job_batch = []
                for _ in range(self.batch_size):
                    try:
                        priority, job_id = self.job_queue.get(timeout=1)
                        job_batch.append(job_id)
                    except queue.Empty:
                        break
                
                if not job_batch:
                    time.sleep(self.polling_interval)
                    continue
                
                # Process batch using Celery
                try:
                    result = self.process_domain_batch.delay(job_batch)
                    logger.info(f"Submitted batch of {len(job_batch)} jobs to Celery")
                except Exception as e:
                    logger.error(f"Failed to submit batch to Celery: {e}")
                    # Mark jobs as failed
                    with self.lock:
                        for job_id in job_batch:
                            if job_id in self.jobs:
                                self.jobs[job_id].status = ProcessingStatus.FAILED
                                self.jobs[job_id].error_message = str(e)
                                self.jobs[job_id].completed_at = datetime.now()
                
            except Exception as e:
                logger.error(f"Processing worker error: {e}")
                time.sleep(self.polling_interval)
    
    def clear_completed_jobs(self, older_than_hours: int = 24):
        """Clear completed jobs older than specified hours"""
        cutoff_time = datetime.now() - timedelta(hours=older_than_hours)
        
        with self.lock:
            jobs_to_remove = []
            for job_id, job in self.jobs.items():
                if (job.status in [ProcessingStatus.COMPLETED, ProcessingStatus.FAILED] and
                    job.completed_at and job.completed_at < cutoff_time):
                    jobs_to_remove.append(job_id)
            
            for job_id in jobs_to_remove:
                del self.jobs[job_id]
            
            logger.info(f"Cleared {len(jobs_to_remove)} old completed jobs")
            return len(jobs_to_remove)
    
    def get_processing_metrics(self) -> Dict[str, Any]:
        """Get processing performance metrics"""
        with self.lock:
            completed_jobs = [job for job in self.jobs.values() if job.status == ProcessingStatus.COMPLETED]
            
            if not completed_jobs:
                return {
                    'total_processed': 0,
                    'average_processing_time': 0,
                    'success_rate': 0,
                    'throughput_per_hour': 0
                }
            
            processing_times = []
            for job in completed_jobs:
                if job.started_at and job.completed_at:
                    processing_times.append(
                        (job.completed_at - job.started_at).total_seconds()
                    )
            
            total_processed = len(completed_jobs)
            failed_count = sum(1 for job in self.jobs.values() if job.status == ProcessingStatus.FAILED)
            success_rate = total_processed / (total_processed + failed_count) if (total_processed + failed_count) > 0 else 0
            
            avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0
            
            # Calculate throughput (jobs per hour)
            if completed_jobs:
                oldest_job = min(completed_jobs, key=lambda x: x.created_at)
                newest_job = max(completed_jobs, key=lambda x: x.completed_at)
                time_span = (newest_job.completed_at - oldest_job.created_at).total_seconds() / 3600
                throughput_per_hour = total_processed / time_span if time_span > 0 else 0
            else:
                throughput_per_hour = 0
            
            return {
                'total_processed': total_processed,
                'average_processing_time': round(avg_processing_time, 2),
                'success_rate': round(success_rate, 2),
                'throughput_per_hour': round(throughput_per_hour, 2),
                'failed_jobs': failed_count
            }
