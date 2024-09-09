import json
from authlib.integrations.django_client import OAuth
from authlib.integrations.requests_client import OAuth2Session
from django.conf import settings
from django.shortcuts import redirect, render, redirect
from django.urls import reverse
from urllib.parse import quote_plus, urlencode
# Lib additions
from django.http import HttpResponse
import requests
import logging
import jwt
from django.contrib.auth.decorators import login_required

logger = logging.getLogger(__name__)

oauth = OAuth()

audience = "api://django-api"

# Django related OAuth client registrations
oauth.register(
    "auth0",
    client_id=settings.AUTH0_CLIENT_ID,
    client_secret=settings.AUTH0_CLIENT_SECRET,
    client_kwargs={
        "scope": "openid profile email",
        "audience": audience,
    },
    server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration"
)

# Passkey App
oauth.register(
    "passkey",
    client_id=settings.AUTH0_CLIENT_ID_PK,
    client_secret=settings.AUTH0_CLIENT_SECRET_PK,
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
)


# Function to decode JWT without verification for display purposes
def decode_jwt(token):
    try:
        return jwt.decode(token, options={"verify_signature": False}, algorithms=["RS256"])
    except Exception as e:
        return str(e)


def index(request):

    return render(
        request,
        "index.html",
        context={
            "session": request.session.get("user"),
            "pretty": json.dumps(request.session.get("user"), indent=4),
        },
    )


# Django decorator to enforce login for profile page
#@login_required
def profile(request):

    print(request.session.get("id_token"))
    print(request.session.get("access_token"))

    # Retrieve tokens & info from the session
    user = request.session.get('user', {})
    id_token = user.get('id_token')
    access_token = user.get('access_token')
    userinfo = user.get('userinfo', {})

    if not id_token or not access_token:
        return HttpResponse("Token missing or invalid", status=400)

    # Decode tokens
    decoded_id_token = decode_jwt(id_token) if id_token else None
    decoded_access_token = decode_jwt(access_token) if access_token else None

    return render(
        request,
        'profile.html',  # Make sure this file is in your templates folder
        context={
            'pretty_id': json.dumps(decoded_id_token, indent=4) if decoded_id_token else "",
            'pretty_access': json.dumps(decoded_access_token, indent=4) if decoded_access_token else "",
            "session": request.session.get("user"),
        }
    )


def callback(request):
    token = oauth.auth0.authorize_access_token(request)
    request.session["user"] = token
    #print(request.session["user"])
    print("Token received:", token)  # Log the token
    return redirect(request.build_absolute_uri(reverse("index")))


def login(request):
    return oauth.auth0.authorize_redirect(
        request,
        request.build_absolute_uri(reverse("callback")),
        audience=audience
    )


def callback_pk(request):
    token = oauth.passkey.authorize_access_token(request)
    request.session["user"] = token
    return redirect(request.build_absolute_uri(reverse("index")))


def passkey(request):
    return oauth.passkey.authorize_redirect(
        request,
        request.build_absolute_uri(reverse("callback_pk")),
        audience=audience
    )


def logout(request):
    print(f"logout request: {request}")
    request.session.clear()

    return redirect(
        f"https://{settings.AUTH0_DOMAIN}/v2/logout?"
        + urlencode(
            {
                "returnTo": request.build_absolute_uri(reverse("index")),
                "client_id": settings.AUTH0_CLIENT_ID,
            },
            quote_via=quote_plus,
        ),
    )


def self_serve(request):
    api = f"https://{settings.AUTH0_DOMAIN}/api/v2/self-service-profiles/{settings.AUTH0_SELFSERVE_ID}/sso-ticket"
    #api = f"https://{settings.AUTH0_DOMAIN}/api/v2/users"
    headers = {
        "Authorization": f"Bearer {settings.AUTH0_API_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        # Change this config name each time we run this!
        "connection_config": {
            "name": "ss-sso-123543125"
        }
    }

    try:
        response = requests.post(api, headers=headers, json=payload)
        #response = requests.get(api, headers=headers)

        logger.debug(f"Response Code: {response.status_code}")
        logger.debug(f"Response Content: {response.content}")

        if response.status_code == 201:
            data = response.json()
            self_serve_url = data.get("ticket")
            if self_serve_url:
                return redirect(self_serve_url)
            else:
                logger.error("Error: 'ticket' not found in the response.")
                return HttpResponse("Error: 'ticket' not found in the response.", status=500)
        else:
            logger.error(f"Error {response.content}")
            return HttpResponse(f"Error: {response.content}", status=500)
    except Exception as e:
        logger.exception("An error occurred while fetching .")
        return HttpResponse("Please try again later.", status=500)

