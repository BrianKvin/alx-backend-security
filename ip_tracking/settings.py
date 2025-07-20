# settings.py - Add these configurations to your Django settings

import os
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'your-secret-key-here'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['*']

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    
    # Third party apps
    'django_ratelimit',
    
    # Local apps
    'ip_tracking',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    
    # Custom IP tracking middleware (should be early in the stack)
    'ip_tracking.middleware.IPTrackingMiddleware',
]

ROOT_URLCONF = 'your_project.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'your_project.wsgi.application'

# Database
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# Redis Cache Configuration (required for IP tracking)
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://127.0.0.1:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

# Celery Configuration
CELERY_BROKER_URL = 'redis://127.0.0.1:6379/0'
CELERY_RESULT_BACKEND = 'redis://127.0.0.1:6379/0'
CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TIMEZONE = 'UTC'

# Celery Beat Schedule for periodic tasks
from celery.schedules import crontab

CELERY_BEAT_SCHEDULE = {
    'detect-anomalous-ips': {
        'task': 'ip_tracking.tasks.detect_anomalous_ips',
        'schedule': crontab(minute=0),  # Run every hour
    },
    'auto-block-suspicious-ips': {
        'task': 'ip_tracking.tasks.auto_block_suspicious_ips',
        'schedule': crontab(minute=30, hour='*/6'),  # Run every 6 hours
    },
    'cleanup-old-logs': {
        'task': 'ip_tracking.tasks.cleanup_old_logs',
        'schedule': crontab(minute=0, hour=2),  # Run daily at 2 AM
    },
    'generate-security-report': {
        'task': 'ip_tracking.tasks.generate_security_report',
        'schedule': crontab(minute=0, hour=8),  # Run daily at 8 AM
    },
    'check-geolocation-consistency': {
        'task': 'ip_tracking.tasks.check_geolocation_consistency',
        'schedule': crontab(minute=0, hour='*/4'),  # Run every 4 hours
    },
}

# Rate limiting configuration
RATELIMIT_ENABLE = True
RATELIMIT_USE_CACHE = 'default'

# For development, you can use a simpler cache
# CACHES = {
#     'default': {
#         'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
#     }
# }

# Rate limit configuration for different user types
RATELIMIT_VIEW = 'ip_tracking.views.ratelimited_error'

# Logging configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': 'INFO',
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'ip_tracking.log',
            'formatter': 'verbose',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        'ip_tracking': {
            'handlers': ['file', 'console'],
            'level': 'INFO',
            'propagate': True,
        },
    },
}

# Security settings for production
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'DENY'

# Internationalization
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
STATIC_ROOT = BASE_DIR / 'staticfiles'

# Default primary key field type
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# IP Tracking specific settings
IP_TRACKING_SETTINGS = {
    'ANOMALY_THRESHOLD': 100,  # Requests per hour
    'SENSITIVE_PATHS': ['/admin', '/login', '/api/login', '/django-admin'],
    'AUTO_BLOCK_THRESHOLD': 3,  # Suspicious activities before auto-block
    'LOG_RETENTION_DAYS': 30,  # Days to keep request logs
    'GEOLOCATION_CACHE_HOURS': 24,  # Hours to cache geolocation data
}