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

oauth.register(
    "auth0",
    client_id=settings.AUTH0_CLIENT_ID,
    client_secret=settings.AUTH0_CLIENT_SECRET,
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f"https://{settings.AUTH0_DOMAIN}/.well-known/openid-configuration",
)


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


def login(request):
    return oauth.auth0.authorize_redirect(
        request, request.build_absolute_uri(reverse("callback"))
    )


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
    api = f"https://{settings.AUTH0_DOMAIN}/api/v2/tickets/sso-access"
    #api = f"https://{settings.AUTH0_DOMAIN}/api/v2/users"
    headers = {
        "Authorization": f"Bearer {settings.AUTH0_API_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "sso_profile_id": f"{settings.AUTH0_SELFSERVE_ID}",
        "connection_config": {
            "name": "self-service-Django"
        },
        "testing_config": {
            "testing_login_url": "https://atko-mv-org.vercel.app/login"
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