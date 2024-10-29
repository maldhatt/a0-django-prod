from django.urls import path

# adding to serve static files for development
from django.conf import settings
from django.conf.urls.static import static

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("profile", views.profile, name="profile"),
    path("login", views.login, name="login"),
    path("logout", views.logout, name="logout"),
    path("callback", views.callback, name="callback"),
    path("callback_pk", views.callback_pk, name="callback_pk"),
    path("callback_pwless_email", views.callback_pwless_email, name="callback_pwless_email"),
    path("callback_pwless_sms", views.callback_pwless_sms, name="callback_pwless_sms"),
    path("callback_orgs", views.callback_orgs, name="callback_orgs"),
    path("passkey", views.passkey, name="passkey"),
    path("login_pwless_email", views.login_pwless_email, name="login_pwless_email"),
    path("login_pwless_sms", views.login_pwless_sms, name="login_pwless_sms"),
    path("login_orgs", views.login_orgs, name="login_orgs"),
    path("Self Serve", views.self_serve, name="Self Serve")
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)  # added this line for Heroku

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)