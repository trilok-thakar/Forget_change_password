from django.urls import path
from .views import *

urlpatterns = [
    path('', Home, name="home"),
    path("login/", Login, name="login"),
    path("register/", Register, name="register"),
    path('verify/<auth_token>/', verify, name='verify'),
    path("forget-password/", ForgetPassword, name="forget_password"),
    path("change-password/<token>/", ChangePassword, name="change-password"),
    path("logout/", Logout, name="logout"),
]

