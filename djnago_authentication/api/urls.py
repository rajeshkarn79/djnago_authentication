from django.urls import path
from .views import *
urlpatterns = [
    path('reg', UserRegistrationAPI.as_view()),
    path('verify', OTPVerify.as_view()),
    path('resend', OTPResend.as_view()),
    path('login', LoginAPI.as_view()),
    path('change_password', ChangePassword.as_view()),
    path('forget', RequestResetPassword.as_view(), name="request for forget password"),
    path('reset', ResetPasswordAPI.as_view()),
    
]
