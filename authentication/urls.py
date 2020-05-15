from django.urls import path
from . import views
from django.contrib.auth.decorators import login_required


urlpatterns = [
    path('register', views.RegistrationView.as_view(), name='register'),
    path('login', views.LoginView.as_view(), name='login'),
    path('logout', views.LogoutView.as_view(), name='logout'),
    path('', login_required(views.HomeView.as_view()), name='home'),
    path('complete-reset/<uidb64>/<token>',
         views.CompletePasswordChangeView.as_view(), name='complete-reset'),
    path('activate/<uidb64>/<token>',
         views.ActivateAccountView.as_view(), name='activate'),
    path('request_reset_email/', views.RequestResetEmail.as_view(),
         name='request_reset_email')
]
