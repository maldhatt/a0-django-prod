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

logger = logging.getLogger(__name__)

oauth = OAuth()

# Django related OAuth client registration
oauth.register(
    "auth0",
    client_id=settings.AUTH0_CLIENT_ID,
    client_secret=settings.AUTH0_CLIENT_SECRET,
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
)

# Trying multi-client oauth registration via authlib
oauth.register(
    "passkey",
    client_id=settings.AUTH0_CLIENT_ID_PK,
    client_secret=settings.AUTH0_CLIENT_SECRET_PK,
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
)

# Client IDs
oauth2Client = OAuth2Session(client_id=settings.AUTH0_CLIENT_ID, client_secret=settings.AUTH0_CLIENT_SECRET, scope="openid profile email")
oauth2Client_pk = OAuth2Session(client_id=settings.AUTH0_CLIENT_ID_PK, client_secret=settings.AUTH0_CLIENT_SECRET_PK, scope="openid profile email")
authorization_endpoint = f"https://{settings.AUTH0_DOMAIN}/authorize"
token_endpoint = f"https://{settings.AUTH0_DOMAIN}/oauth/token"

redirect_uri = "http://localhost:3000/callback"


# Building custom Auth0 URL
def build_authorization_url(client_id, redirect_uri, scope="openid profile email"):
    base_url = f"https://{settings.AUTH0_DOMAIN}/authorize"
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
    }

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
    token = oauth.auth0.authorize_access_token(request)
    request.session["user"] = token
    return redirect(request.build_absolute_uri(reverse("index")))

# def callback(request):
#     print(f"callback request: {request}")
#     #token = oauth.auth0.authorize_access_token(request)
#     authorization_response = request.build_absolute_uri()
#     token = oauth2Client.fetch_token(token_endpoint, authorization_response=authorization_response,
#                                      redirect_uri=redirect_uri)
#     request.session["user"] = token
#     #print(f"Session Data After Set: {request.session.get('user')}")
#     return redirect(request.build_absolute_uri(reverse("index")))


def login(request):
    return oauth.auth0.authorize_redirect(
        request, request.build_absolute_uri(reverse("callback"))
    )

# def login(request):
#     redirect_uri = request.build_absolute_uri(reverse("callback"))
#     auth_url = build_authorization_url(settings.AUTH0_CLIENT_ID, redirect_uri)
#     print(f"Login auth_url: {auth_url}")
#     return redirect(auth_url)


def callback_pk(request):
    token = oauth.passkey.authorize_access_token(request)
    request.session["user"] = token
    return redirect(request.build_absolute_uri(reverse("index")))


# def callback_pk(request):
#     print(f"callback request: {request}")
#     authorization_response = request.build_absolute_uri()
#     # Swap OAuth Clients for separate client_IDs
#     token = oauth2Client_pk.fetch_token(token_endpoint, authorization_response=authorization_response,
#                                      redirect_uri=redirect_uri)
#     request.session["user"] = token
#     return redirect(request.build_absolute_uri(reverse("index")))


# def passkey(request):
#     redirect_uri = request.build_absolute_uri(reverse("callback_pk"))
#     # Swap Client IDs
#     auth_url = build_authorization_url(settings.AUTH0_CLIENT_ID_PK, redirect_uri)
#     return redirect(auth_url)

def passkey(request):
    return oauth.passkey.authorize_redirect(
        request, request.build_absolute_uri(reverse("callback_pk"))
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


    # This is the default Auth0 SDK language
    # def login(request):
    #     #oauth.auth0.client_kwargs["client_id"]=settings.AUTH0_CLIENT_ID
    #     return oauth.auth0.authorize_redirect(
    #         request, request.build_absolute_uri(reverse("callback"))
    #         #client_id=settings.AUTH0_CLIENT_ID
    #     )
