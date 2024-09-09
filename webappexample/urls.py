from django.urls import path

# adding to serve static files for development
from django.conf import settings
from django.conf.urls.static import static

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path('profile', views.profile, name='profile'),
    path("login", views.login, name="login"),
    path("logout", views.logout, name="logout"),
    path("callback", views.callback, name="callback"),
    path("callback_pk", views.callback_pk, name="callback_pk"),
    path("passkey", views.passkey, name="passkey"),
    path("Self Serve", views.self_serve, name="Self Serve")
]

if settings.DEBUG:
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
