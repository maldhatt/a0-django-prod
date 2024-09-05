import json
from authlib.integrations.django_client import OAuth
from django.conf import settings
from django.shortcuts import redirect, render, redirect
from django.urls import reverse
from urllib.parse import quote_plus, urlencode
# Lib additions
from django.http import HttpResponse
import requests
import logging

logger = logging.getLogger(__name__)

oauth = OAuth()

# To pass in multiple client_ids, still pass in client_ID dynamically later
oauth.register(
    "auth0",
    client_secret=settings.AUTH0_CLIENT_SECRET,
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
)

# Trying building Auth0 URL
def build_authorization_url(client_id, redirect_uri, state=None, scope="openid profile email"):
    base_url = f"https://{settings.AUTH0_DOMAIN}/authorize"
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }

    if state:
        params["state"] = state

    return f"{base_url}?{urlencode(params)}"


def index(request):

    return render(
        request,
        "index.html",
        context={
            "session": request.session.get("user"),
            "pretty": json.dumps(request.session.get("user"), indent=4),
        },
    )


def callback(request):
    """
    session_state = request.session.session_key
    print(f"Session Key in callback: {session_state}")

    # Attempt to authorize the token and check for any issues
    try:
        token = oauth.auth0.authorize_access_token(request)
        print(f"Token received: {token}")
    except Exception as e:
        print(f"Error in authorize_access_token: {str(e)}")
        raise

    # Ensure the state from Auth0 matches the session state
    if token.get('state') != session_state:
        print(f"State mismatch! Token state: {token.get('state')}, Session state: {session_state}")
        raise Exception("State mismatch! Possible CSRF attack.")

    # Store user info in the session after successful state check
    request.session["user"] = token
    print(f"Session Data After Set: {request.session.get('user')}")

    return redirect(request.build_absolute_uri(reverse("index")))
    """
    token = oauth.auth0.authorize_access_token(request)
    request.session["user"] = token
    print(f"Session Data After Set: {request.session.get('user')}")
    return redirect(request.build_absolute_uri(reverse("index")))


def login(request):
    """
    if not request.session.session_key:
        request.session.create()
        print(f"New Session Key Created: {request.session.session_key}")  # Verify the session key creation

    state = request.session.session_key
    """
    redirect_uri = request.build_absolute_uri(reverse("callback"))
    auth_url = build_authorization_url(settings.AUTH0_CLIENT_ID, redirect_uri)
    return redirect(auth_url)

"""
This is the default Auth0 SDK language
def login(request):
    oauth.auth0.client_kwargs["client_id"]=settings.AUTH0_CLIENT_ID
    return oauth.auth0.authorize_redirect(
        request, request.build_absolute_uri(reverse("callback"))
        #client_id=settings.AUTH0_CLIENT_ID
    ) 
"""

def passkey(request):
    redirect_uri = request.build_absolute_uri(reverse("callback"))
    # Swap Client IDs
    auth_url = build_authorization_url(settings.AUTH0_CLIENT_ID_PK, redirect_uri)
    return redirect(auth_url)

def logout(request):
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