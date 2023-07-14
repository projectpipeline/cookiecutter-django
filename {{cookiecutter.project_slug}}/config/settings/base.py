"""
Base settings to build other settings files upon.
"""
import json
import boto3 as boto3
import environ

from distutils.util import strtobool
from pathlib import Path
from urllib import request
from django.utils.translation import gettext_lazy as _

BASE_DIR = Path(__file__).resolve(strict=True).parent.parent.parent
# {{ cookiecutter.project_slug }}/
APPS_DIR = BASE_DIR / "{{ cookiecutter.project_slug }}"
env = environ.Env()

READ_DOT_ENV_FILE = env.bool("DJANGO_READ_DOT_ENV_FILE", default=False)
if READ_DOT_ENV_FILE:
    # OS environment variables take precedence over variables from .env
    env.read_env(str(BASE_DIR / ".env"))

{%- if cookiecutter.cloud_provider == 'AWS' %}
AWS_ACCOUNT = env.str('AWS_ACCOUNT', default=None)
AWS_REGION = env.str('AWS_REGION', default='ca-central-1')
AWS_SES_REGION_NAME = env.str('AWS_SES_REGION_NAME', default='ca-central-1')
AWS_SES_REGION_ENDPOINT = env.str('AWS_SES_REGION_ENDPOINT', default=f'email.{AWS_SES_REGION_NAME}.amazonaws.com')

# Configure the AWS environment
ENV = env.str('ENV', default=None)

print(f"ENV is {ENV}")

CONFIG = {'env': ENV, 'debug': False}

DEVELOP = env.bool('DEVELOP', default=False)

KEY = env.str('KEY', default=ENV)
rsa_keys = {}

# Provide this value if `id_token` is used for authentication (it contains 'aud' claim).
# `access_token` doesn't have it, in this case keep the COGNITO_AUDIENCE empty
COGNITO_AUDIENCE = None
COGNITO_POOL_URL = None  # will be set few lines of code later, if configuration provided

CONFIG['account'] = AWS_ACCOUNT
CONFIG['region'] = AWS_REGION
path = "/{0}/".format(ENV)

session = boto3.session.Session()
client = session.client(
    service_name='ssm',
    region_name=CONFIG['region'],
)
response = client.get_parameters_by_path(
    Path=path,
    Recursive=True,
)
for param in response['Parameters']:
    CONFIG[param['Name'].replace(path, '')] = param['Value']

while response.get('NextToken', None) is not None:
    response = client.get_parameters_by_path(
        Path=path,
        Recursive=True,
        NextToken=response['NextToken']
    )
    for param in response['Parameters']:
        CONFIG[param['Name'].replace(path, '')] = param['Value']

CONFIG['db_ssl_ca'] = 'rds-ca-2019-root.pem'

COGNITO_AWS_REGION = AWS_REGION
COGNITO_USER_POOL = CONFIG['COGNITO_USER_POOL']

# To avoid circular imports, we keep this logic here.
# On django init we download jwks public keys which are used to validate jwt tokens.
# For now there is no rotation of keys (seems like in Cognito decided not to implement it)
if COGNITO_AWS_REGION and COGNITO_USER_POOL:
    COGNITO_POOL_URL = 'https://cognito-idp.{}.amazonaws.com/{}'.format(COGNITO_AWS_REGION, COGNITO_USER_POOL)
    pool_jwks_url = COGNITO_POOL_URL + '/.well-known/jwks.json'
    jwks = json.loads(request.urlopen(pool_jwks_url).read())
    rsa_keys = {key['kid']: json.dumps(key) for key in jwks['keys']}

JWT_AUTH = {
    'JWT_PAYLOAD_GET_USERNAME_HANDLER': '{{cookiecutter.project_slug}}.utils.jwt.get_username_from_payload_handler',
    'JWT_DECODE_HANDLER': '{{cookiecutter.project_slug}}.utils.jwt.cognito_jwt_decode_handler',
    'JWT_PUBLIC_KEY': rsa_keys,
    'JWT_ALGORITHM': 'RS256',
    'JWT_AUDIENCE': COGNITO_AUDIENCE,
    'JWT_ISSUER': COGNITO_POOL_URL,
    'JWT_AUTH_HEADER_PREFIX': 'Bearer',
}

{%- endif %}


# GENERAL
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#debug
DEBUG = env.bool("DJANGO_DEBUG", False)
# Local time zone. Choices are
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# though not all of them may be available with every OS.
# In Windows, this must be set to your system time zone.
TIME_ZONE = "{{ cookiecutter.timezone }}"
# https://docs.djangoproject.com/en/dev/ref/settings/#language-code
LANGUAGE_CODE = "en-us"
# https://docs.djangoproject.com/en/dev/ref/settings/#site-id
SITE_ID = 1
# https://docs.djangoproject.com/en/dev/ref/settings/#use-i18n
USE_I18N = True
# https://docs.djangoproject.com/en/dev/ref/settings/#use-tz
USE_TZ = True
# https://docs.djangoproject.com/en/dev/ref/settings/#locale-paths
LOCALE_PATHS = [str(BASE_DIR / "locale")]

# DATABASES
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#databases
{% if cookiecutter.use_docker == "y" or cookiecutter.use_sqlite == "y" -%}
DATABASES = {"default": env.db("DATABASE_URL")}
{%- else %}
DATABASES = {
    'default': {
        'ENGINE': env.str('DB_ENGINE', default='django_iam_dbauth.aws.mysql'),
        'NAME':  env.str('DB_DATABASE', default=CONFIG.get('DB_DATABASE')),
        'USER': env.str('DB_USER', default=CONFIG.get('DB_USER')),
        'PASSWORD': env.str("DB_PASS", default=''),
        'HOST': env.str('DB_HOST', default=CONFIG.get('DB_HOSTWRITE', '')),
        'PORT': env.str('DB_PORT', default='3306'),
        'ATOMIC_REQUESTS': True,
        'OPTIONS': {
            'ssl': {
                'MYSQL_OPT_SSL_CAPATH': 'rds-ca-2019-root.pem'
            },
            'sql_mode': 'TRADITIONAL',
            "use_iam_auth": True,
            'charset': 'utf8mb4'
        },
    }
}
{%- endif %}
DATABASES["default"]["ATOMIC_REQUESTS"] = True

SESSION_ENGINE = env.str('SESSION_ENGINE', default='django.contrib.sessions.backends.cached_db')
SESSION_CACHE_ALIAS = 'default'

EMAIL_HOST = CONFIG.get('SMTP_HOST')
EMAIL_PORT = 587

EMAIL_USE_TLS = bool(strtobool(CONFIG.get('EMAIL_USE_TLS', 'True')))
EMAIL_HOST_USER = CONFIG.get('SMTP_USER')
EMAIL_HOST_PASSWORD = CONFIG.get('SMTP_PASSWORD')
SERVER_EMAIL = CONFIG.get('DEFAULT_FROM_EMAIL', "")

# https://docs.djangoproject.com/en/stable/ref/settings/#std:setting-DEFAULT_AUTO_FIELD
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# URLS
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#root-urlconf
ROOT_URLCONF = "config.urls"
# https://docs.djangoproject.com/en/dev/ref/settings/#wsgi-application
WSGI_APPLICATION = "config.wsgi.application"

# APPS
# ------------------------------------------------------------------------------
DJANGO_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.sites",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    # "django.contrib.humanize", # Handy template tags
    "django.contrib.admin",
    "django.contrib.admindocs",
    "django.forms",
]
THIRD_PARTY_APPS = [
    'guardian',
    "crispy_forms",
    "crispy_bootstrap5",
    "allauth",
    "allauth.account",
    "allauth.socialaccount",
{%- if cookiecutter.use_celery == 'y' %}
    "django_celery_beat",
{%- endif %}
{%- if cookiecutter.use_drf == "y" %}
    "rest_framework",
    "rest_framework.authtoken",
    "corsheaders",
    "drf_spectacular",
{%- endif %}
{%- if cookiecutter.frontend_pipeline == 'Webpack' %}
    "webpack_loader",
{%- endif %}
]

LOCAL_APPS = [
    {%- for app in local_apps %}
    "{{ cookiecutter.project_slug }}.{{ app }}",
    {%- endfor %}
    "{{ cookiecutter.project_slug }}.users",
    "{{ cookiecutter.project_slug }}.base",
    'jet.dashboard',
    'jet',
    # Your stuff: custom apps go here
]
# https://docs.djangoproject.com/en/dev/ref/settings/#installed-apps
INSTALLED_APPS = DJANGO_APPS + THIRD_PARTY_APPS + LOCAL_APPS

# MIGRATIONS
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#migration-modules
MIGRATION_MODULES = {"sites": "{{ cookiecutter.project_slug }}.contrib.sites.migrations"}

# AUTHENTICATION
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#authentication-backends
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    'django.contrib.auth.backends.RemoteUserBackend',
    "allauth.account.auth_backends.AuthenticationBackend",
    'guardian.backends.ObjectPermissionBackend',

]
# https://docs.djangoproject.com/en/dev/ref/settings/#auth-user-model
AUTH_USER_MODEL = "users.User"
# https://docs.djangoproject.com/en/dev/ref/settings/#login-redirect-url
LOGIN_REDIRECT_URL = "users:redirect"
# https://docs.djangoproject.com/en/dev/ref/settings/#login-url
LOGIN_URL = "account_login"

# PASSWORDS
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#password-hashers
PASSWORD_HASHERS = [
    # https://docs.djangoproject.com/en/dev/topics/auth/passwords/#using-argon2-with-django
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]
# https://docs.djangoproject.com/en/dev/ref/settings/#auth-password-validators
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# MIDDLEWARE
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#middleware
MIDDLEWARE = [
    "{{cookiecutter.project_slug}}.utils.middlewares.SetRemoteAddrFromForwardedFor",
    "django.middleware.security.SecurityMiddleware",
{%- if cookiecutter.use_drf == 'y' %}
    "corsheaders.middleware.CorsMiddleware",
{%- endif %}
{%- if cookiecutter.use_whitenoise == 'y' %}
    "whitenoise.middleware.WhiteNoiseMiddleware",
{%- endif %}
    "django.contrib.sessions.middleware.SessionMiddleware",
    'django.middleware.http.ConditionalGetMiddleware',
    "django.middleware.locale.LocaleMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    'django.contrib.auth.middleware.RemoteUserMiddleware',
    'django.contrib.admindocs.middleware.XViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# STATIC
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#static-root
STATIC_ROOT = str(BASE_DIR / "staticfiles")
# https://docs.djangoproject.com/en/dev/ref/settings/#static-url
STATIC_URL = "/static/"
# https://docs.djangoproject.com/en/dev/ref/contrib/staticfiles/#std:setting-STATICFILES_DIRS
STATICFILES_DIRS = [str(APPS_DIR / "static")]
# https://docs.djangoproject.com/en/dev/ref/contrib/staticfiles/#staticfiles-finders
STATICFILES_FINDERS = [
    "django.contrib.staticfiles.finders.FileSystemFinder",
    "django.contrib.staticfiles.finders.AppDirectoriesFinder",
]

# MEDIA
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#media-root
MEDIA_ROOT = str(APPS_DIR / "media")
# https://docs.djangoproject.com/en/dev/ref/settings/#media-url
MEDIA_URL = "/media/"

# TEMPLATES
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#templates
TEMPLATES = [
    {
        # https://docs.djangoproject.com/en/dev/ref/settings/#std:setting-TEMPLATES-BACKEND
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        # https://docs.djangoproject.com/en/dev/ref/settings/#dirs
        "DIRS": [str(APPS_DIR / "templates")],
        # https://docs.djangoproject.com/en/dev/ref/settings/#app-dirs
        "APP_DIRS": True,
        "OPTIONS": {
            # https://docs.djangoproject.com/en/dev/ref/settings/#template-context-processors
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.template.context_processors.i18n",
                "django.template.context_processors.media",
                "django.template.context_processors.static",
                "django.template.context_processors.tz",
                "django.contrib.messages.context_processors.messages",
                "{{cookiecutter.project_slug}}.users.context_processors.allauth_settings",
            ],
        },
    }
]

# https://docs.djangoproject.com/en/dev/ref/settings/#form-renderer
FORM_RENDERER = "django.forms.renderers.TemplatesSetting"

# http://django-crispy-forms.readthedocs.io/en/latest/install.html#template-packs
CRISPY_TEMPLATE_PACK = "bootstrap5"
CRISPY_ALLOWED_TEMPLATE_PACKS = "bootstrap5"

# FIXTURES
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#fixture-dirs
FIXTURE_DIRS = (str(APPS_DIR / "fixtures"),)

# SECURITY
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#session-cookie-httponly
SESSION_COOKIE_HTTPONLY = True
# https://docs.djangoproject.com/en/dev/ref/settings/#csrf-cookie-httponly
CSRF_COOKIE_HTTPONLY = True
# https://docs.djangoproject.com/en/dev/ref/settings/#x-frame-options
X_FRAME_OPTIONS = "SAMEORIGIN"

# EMAIL
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#email-backend
EMAIL_BACKEND = env(
    "DJANGO_EMAIL_BACKEND",
    default="django.core.mail.backends.smtp.EmailBackend",
)
# https://docs.djangoproject.com/en/dev/ref/settings/#email-timeout
EMAIL_TIMEOUT = 5

# ADMIN
# ------------------------------------------------------------------------------
# Django Admin URL.
ADMIN_URL = "admin/"
# https://docs.djangoproject.com/en/dev/ref/settings/#admins
ADMINS = [("""{{cookiecutter.author_name}}""", "{{cookiecutter.email}}")]
# https://docs.djangoproject.com/en/dev/ref/settings/#managers
MANAGERS = ADMINS
MESSAGE_STORAGE = 'django.contrib.messages.storage.session.SessionStorage'
USE_ETAGS = True
# LOGGING
# ------------------------------------------------------------------------------
# https://docs.djangoproject.com/en/dev/ref/settings/#logging
# See https://docs.djangoproject.com/en/dev/topics/logging for
# more details on how to customize your logging configuration.
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "%(levelname)s %(asctime)s %(module)s "
            "%(process)d %(thread)d %(message)s"
        }
    },
    "handlers": {
        "console": {
            "level": "DEBUG",
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        }
    },
    "root": {"level": "INFO", "handlers": ["console"]},
}

{% if cookiecutter.use_celery == 'y' -%}
# Celery
# ------------------------------------------------------------------------------
if USE_TZ:
    # https://docs.celeryq.dev/en/stable/userguide/configuration.html#std:setting-timezone
    CELERY_TIMEZONE = TIME_ZONE
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#std:setting-broker_url
CELERY_BROKER_URL = env("CELERY_BROKER_URL")
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#std:setting-result_backend
CELERY_RESULT_BACKEND = CELERY_BROKER_URL
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#result-extended
CELERY_RESULT_EXTENDED = True
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#result-backend-always-retry
# https://github.com/celery/celery/pull/6122
CELERY_RESULT_BACKEND_ALWAYS_RETRY = True
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#result-backend-max-retries
CELERY_RESULT_BACKEND_MAX_RETRIES = 10
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#std:setting-accept_content
CELERY_ACCEPT_CONTENT = ["json"]
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#std:setting-task_serializer
CELERY_TASK_SERIALIZER = "json"
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#std:setting-result_serializer
CELERY_RESULT_SERIALIZER = "json"
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#task-time-limit
# TODO: set to whatever value is adequate in your circumstances
CELERY_TASK_TIME_LIMIT = 5 * 60
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#task-soft-time-limit
# TODO: set to whatever value is adequate in your circumstances
CELERY_TASK_SOFT_TIME_LIMIT = 60
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#beat-scheduler
CELERY_BEAT_SCHEDULER = "django_celery_beat.schedulers:DatabaseScheduler"
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#worker-send-task-events
CELERY_WORKER_SEND_TASK_EVENTS = True
# https://docs.celeryq.dev/en/stable/userguide/configuration.html#std-setting-task_send_sent_event
CELERY_TASK_SEND_SENT_EVENT = True

{%- endif %}
# django-allauth
# ------------------------------------------------------------------------------
ACCOUNT_ALLOW_REGISTRATION = env.bool("DJANGO_ACCOUNT_ALLOW_REGISTRATION", True)
# https://django-allauth.readthedocs.io/en/latest/configuration.html
ACCOUNT_AUTHENTICATION_METHOD = "username"
# https://django-allauth.readthedocs.io/en/latest/configuration.html
ACCOUNT_EMAIL_REQUIRED = True
# https://django-allauth.readthedocs.io/en/latest/configuration.html
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
# https://django-allauth.readthedocs.io/en/latest/configuration.html
ACCOUNT_ADAPTER = "{{cookiecutter.project_slug}}.users.adapters.AccountAdapter"
# https://django-allauth.readthedocs.io/en/latest/forms.html
ACCOUNT_FORMS = {"signup": "{{cookiecutter.project_slug}}.users.forms.UserSignupForm"}
# https://django-allauth.readthedocs.io/en/latest/configuration.html
SOCIALACCOUNT_ADAPTER = "{{cookiecutter.project_slug}}.users.adapters.SocialAccountAdapter"
# https://django-allauth.readthedocs.io/en/latest/forms.html
SOCIALACCOUNT_FORMS = {"signup": "{{cookiecutter.project_slug}}.users.forms.UserSocialSignupForm"}
{% if cookiecutter.frontend_pipeline == 'Django Compressor' -%}
# django-compressor
# ------------------------------------------------------------------------------
# https://django-compressor.readthedocs.io/en/latest/quickstart/#installation
INSTALLED_APPS += ["compressor"]
STATICFILES_FINDERS += ["compressor.finders.CompressorFinder"]
{%- endif %}
{% if cookiecutter.use_drf == "y" -%}
# django-rest-framework
# -------------------------------------------------------------------------------
# django-rest-framework - https://www.django-rest-framework.org/api-guide/settings/
REST_FRAMEWORK = {
    'DEFAULT_VERSIONING_CLASS': 'smarterblinds.versioning.SmarterBlindsVersioning',
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    'DEFAULT_RENDERER_CLASSES': [
        'rest_framework.renderers.JSONRenderer',
        'rest_framework.renderers.BrowsableAPIRenderer',
        'rest_framework.renderers.AdminRenderer',
    ],
    'DEFAULT_PAGINATION_CLASS': '{{cookiecutter.project_slug}}.utils.pagination.ResultSetPagination',
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
    ),
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '12/minute',
    },
    'DEFAULT_FILTER_BACKENDS': [
        'django_filters.rest_framework.DjangoFilterBackend',
        'rest_framework.filters.SearchFilter', 'rest_framework.filters.OrderingFilter'
    ],
    'PAGE_SIZE': 1000,
}

# django-cors-headers - https://github.com/adamchainz/django-cors-headers#setup
CORS_URLS_REGEX = r"^/api/.*$"
CORS_ORIGIN_ALLOW_ALL = bool(strtobool(CONFIG.get('CORS_ORIGIN_ALLOW_ALL', 'True')))
CACHE_MIDDLEWARE_KEY_PREFIX = env.str('CACHE_MIDDLEWARE_KEY_PREFIX', default=f'fpcache_{KEY}')
EMAIL_BACKEND = env.str('EMAIL_BACKEND', default='django_ses.SESBackend')
SECURE_PROXY_SSL_HEADER = env.str('HTTP_X_FORWARDED_PROTO', 'https')
USE_X_FORWARDED_HOST = env.bool('USE_X_FORWARDED_HOST', default=False)
USE_X_FORWARDED_PORT = env.bool('USE_X_FORWARDED_PORT', default=False)
SESSION_COOKIE_SECURE = env.bool('SESSION_COOKIE_SECURE', default=False)
SESSION_COOKIE_DOMAIN = env.str('SESSION_COOKIE_DOMAIN', default=f".{CONFIG.get('DOMAIN_ROOT')}")
CSRF_TRUSTED_ORIGINS = env.list('CSRF_TRUSTED_ORIGINS', default=f"{CONFIG.get('DOMAIN_ROOT')}")
SECURE_BROWSER_XSS_FILTER = bool(strtobool(CONFIG.get('SECURE_BROWSER_XSS_FILTER', 'False')))
SECURE_CONTENT_TYPE_NOSNIFF = bool(strtobool(CONFIG.get('SECURE_CONTENT_TYPE_NOSNIFF', 'False')))
SECURE_HSTS_SECONDS = int(CONFIG.get('SECURE_HSTS_SECONDS', 3600))
SECURE_SSL_REDIRECT = bool(strtobool(CONFIG.get('SECURE_SSL_REDIRECT', 'False')))
CORS_ORIGIN_WHITELIST = CONFIG.get('CORS_ORIGIN_WHITELIST', "http://example.com").split(",")
DEFAULT_FROM_EMAIL = CONFIG.get('DEFAULT_FROM_EMAIL', "")


# By Default swagger ui is available only to admin user(s). You can change permission classes to change that
# See more configuration options at https://drf-spectacular.readthedocs.io/en/latest/settings.html#settings
SPECTACULAR_SETTINGS = {
    "TITLE": "{{ cookiecutter.project_name }} API",
    "DESCRIPTION": "Documentation of API endpoints of {{ cookiecutter.project_name }}",
    "VERSION": "1.0.0",
    "SERVE_PERMISSIONS": ["rest_framework.permissions.IsAdminUser"],
}
{%- endif %}
{%- if cookiecutter.frontend_pipeline == 'Webpack' %}
# django-webpack-loader
# ------------------------------------------------------------------------------
WEBPACK_LOADER = {
    "DEFAULT": {
        "CACHE": not DEBUG,
        "STATS_FILE": BASE_DIR / "webpack-stats.json",
        "POLL_INTERVAL": 0.1,
        "IGNORE": [r".+\.hot-update.js", r".+\.map"],
    }
}

{%- endif %}
# Your stuff...
# ------------------------------------------------------------------------------

LANGUAGES = [
    ('en', _('English')),
    ('fr', _('French')),
]

ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "mandatory"
LOGIN_REDIRECT_URL = '/#/overview'
LOGIN_URL = '/#/login'
ACCOUNT_DEFAULT_HTTP_PROTOCOL = 'https'
ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION = True
ACCOUNT_LOGIN_ON_PASSWORD_RESET = True
ACCOUNT_LOGOUT_REDIRECT_URL = '/#/login'
OLD_PASSWORD_FIELD_ENABLED = True
LOGOUT_ON_PASSWORD_CHANGE = True
