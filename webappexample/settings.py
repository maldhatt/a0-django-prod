import os
from pathlib import Path
from dotenv import load_dotenv, find_dotenv

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = os.path.join(BASE_DIR, "webappexample", "templates")

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# changed this for Herkou
SECRET_KEY = os.environ.get('SECRET_KEY')

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = False

# Added for Heroku
ALLOWED_HOSTS = ["halden0.herokuapp.com", "halden0-323d4b292113.herokuapp.com", "127.0.0.1", "localhost"]

# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # adding white noise for Heroku
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# Adding weird sessions stuff becuase Auth0 is not working
# SESSION_COOKIE_SECURE setting to false is for development without SSL as Django may require
# HTTPS for secure cookies
#SESSION_ENGINE = 'django.contrib.sessions.backends.signed_cookies'
#SESSION_COOKIE_SECURE = False

ROOT_URLCONF = "webappexample.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [TEMPLATE_DIR],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "webappexample.wsgi.application"


# Database
# https://docs.djangoproject.com/en/4.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.0/topics/i18n/

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"


# Load environment definition file

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)


# Load Auth0 application settings into memory

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
AUTH0_CLIENT_ID_PK = os.environ.get("AUTH0_CLIENT_ID_PK")
AUTH0_CLIENT_ID_PWLESS_E = os.environ.get("AUTH0_CLIENT_ID_PWLESS_E")
AUTH0_CLIENT_ID_PWLESS_SMS = os.environ.get("AUTH0_CLIENT_ID_PWLESS_SMS")
AUTH0_CLIENT_ID_ORGS = os.environ.get("AUTH0_CLIENT_ID_ORGS")
AUTH0_CLIENT_ID_SELFSERVE = os.environ.get("AUTH0_CLIENT_ID_SELFSERVE")
AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET")
AUTH0_CLIENT_SECRET_PK = os.environ.get("AUTH0_CLIENT_SECRET_PK")
AUTH0_CLIENT_SECRET_PWLESS_E = os.environ.get("AUTH0_CLIENT_SECRET_PWLESS_E")
AUTH0_CLIENT_SECRET_PWLESS_SMS = os.environ.get("AUTH0_CLIENT_SECRET_PWLESS_SMS")
AUTH0_CLIENT_SECRET_ORGS = os.environ.get("AUTH0_CLIENT_SECRET_ORGS")
AUTH0_CLIENT_SECRET_SELFSERVE = os.environ.get("AUTH0_CLIENT_SECRET_SELFSERVE")
AUTH0_API_TOKEN = os.environ.get("AUTH0_API_TOKEN")
AUTH0_SELFSERVE_ID = os.environ.get("AUTH0_SELFSERVE_ID")


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = '/static/'
# Adding more
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, "webappexample", "static"),
]

# Changed below for Heroku

STATIC_ROOT = BASE_DIR / 'staticfiles'
#STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# Media files (user-uploaded content)
MEDIA_URL = '/images/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'static/images')