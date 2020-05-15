from django.urls import path
from . import views
from django.contrib.auth.decorators import login_required


urlpatterns = [
    path('register', views.RegistrationView.as_view(), name='register'),
    path('login', views.LoginView.as_view(), name='login'),
    path('logout', views.LogoutView.as_view(), name='logout'),
    path('', login_required(views.HomeView.as_view()), name='home'),
    path('activate/<uidb64>/<token>',
         views.ActivateAccountView.as_view(), name='activate'),
    path('set-new-password/<uidb64>/<token>',
         views.SetNewPasswordView.as_view(), name='set-new-password'),
    path('request-reset-email', views.RequestResetEmailView.as_view(),
         name='request-reset-email')
]
