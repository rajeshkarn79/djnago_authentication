from rest_framework import serializers
from .models import *

class UserRegistration(serializers.Serializer):
    role = serializers.CharField()
    email = serializers.EmailField()
    full_name = serializers.CharField()
    mobile_number = serializers.CharField()
    dob = serializers.CharField()
    address = serializers.CharField()
    password = serializers.CharField()


class EmailVerifySerializers(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    


class ResendOTPSerializers(serializers.Serializer):
    email = serializers.EmailField()


class Loginserializers(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)


class RequestResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField()
    new_password = serializers.CharField(required=True)