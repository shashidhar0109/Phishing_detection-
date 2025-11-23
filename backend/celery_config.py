"""
Celery Configuration for Background Processing
"""

import os
from kombu import Queue

# Redis configuration
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')

# Celery configuration
CELERY_BROKER_URL = REDIS_URL
CELERY_RESULT_BACKEND = REDIS_URL

# Task settings
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TIMEZONE = 'UTC'
CELERY_ENABLE_UTC = True

# Task routing
CELERY_TASK_ROUTES = {
    'backend.queue_processor.process_domain_batch': {'queue': 'domain_processing'},
    'backend.worker.scan_domains': {'queue': 'domain_scanning'},
    'backend.worker.process_detection': {'queue': 'detection_processing'},
}

# Queue configuration
CELERY_TASK_DEFAULT_QUEUE = 'default'
CELERY_TASK_QUEUES = (
    Queue('default'),
    Queue('domain_processing'),
    Queue('domain_scanning'),
    Queue('detection_processing'),
)

# Worker settings
CELERY_WORKER_CONCURRENCY = 4
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
CELERY_TASK_ACKS_LATE = True
CELERY_WORKER_DISABLE_RATE_LIMITS = True

# Task execution settings
CELERY_TASK_TIME_LIMIT = 300  # 5 minutes
CELERY_TASK_SOFT_TIME_LIMIT = 240  # 4 minutes
CELERY_WORKER_MAX_TASKS_PER_CHILD = 50

# Result backend settings
CELERY_RESULT_EXPIRES = 3600  # 1 hour
CELERY_TASK_TRACK_STARTED = True
CELERY_TASK_SEND_SENT_EVENT = True

# Beat schedule (for periodic tasks)
CELERY_BEAT_SCHEDULE = {
    'process-threat-intel': {
        'task': 'backend.worker.process_threat_intelligence',
        'schedule': 300.0,  # Every 5 minutes
    },
    'cleanup-old-jobs': {
        'task': 'backend.worker.cleanup_old_jobs',
        'schedule': 3600.0,  # Every hour
    },
    'update-feed-cache': {
        'task': 'backend.worker.update_threat_feeds',
        'schedule': 1800.0,  # Every 30 minutes
    },
}
