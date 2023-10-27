from .serializers import *
from .models import *
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
import string, random
from django.core.mail import send_mail
from django.contrib.auth.hashers import make_password
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.encoding import smart_str, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import AuthenticationFailed






def send_otp(email):
    char = string.ascii_letters +string.digits
    otp = "".join(random.choice(char) for _ in range(6))
    user = User.objects.get(email=email)
    if user.is_active == False:
        subject = "One-Time Password (OTP) for User Verification"
        messege = f"Dear {user.full_name},\n\nYour OTP is {otp}\nThank you for choosing our service. To ensure the security of your account and to complete the user verification process, we have generated a one-time password (OTP) for you.\nPlease enter this OTP on our website or application to verify your account. This OTP is valid for a Three miuntes, so we recommend completing the verification process as soon as possible.\nIf you did not request this OTP or have any concerns about your account's security, please contact our support team immediately.\nThank you for trusting us with your user verification.\nWe look forward to providing you with a secure and seamless experience.\n\n\n\nSincerely,\n(Team RK) "
        email_from = settings.EMAIL_HOST_USER
        send_mail(subject, messege, email_from, [email])
        OTP_Master.objects.create(email=user, otp=otp)
        return "Your One-Time Password (OTP) has been sent to Your Email."
    return "Your account has already been verified"



class UserRegistrationAPI(APIView):
    serializer_class = UserRegistration
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            email = User.objects.get(email=serializer.data['email'])
            res = send_otp(email)
            return Response(res)
        except User.DoesNotExist:
            email = User.objects.create(email=serializer.data['email'], role = serializer.data['role'], full_name=serializer.data['full_name'], mobile_number=serializer.data['mobile_number'], dob=serializer.data['dob'], address= serializer.data['address'], password = make_password(serializer.data['password']))
            res = send_otp(email)
            return Response(res)
        except Exception as e:
            return Response(str(e))


class OTPVerify(APIView):
    def post(self, request):
        serializer = EmailVerifySerializers(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            otp = serializer.validated_data['otp']
            
            try:
                user = User.objects.get(email=email)
                otp_instance = OTP_Master.objects.filter(email=user).last()
                if otp_instance and otp_instance.is_valid() and otp_instance.otp == otp:
                    user.is_active = True
                    user.save()
                    return Response({"msg": "Your account has been successfully verified."})
                elif otp_instance and not otp_instance.is_valid():
                    return Response({"msg": "Your OTP has expired. Please Resend."}, status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"msg": "Wrong OTP. Please try again"}, status=status.HTTP_400_BAD_REQUEST)
            except User.DoesNotExist:
                return Response({"msg": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class OTPResend(APIView):
    def post(self, request):
        serializer = ResendOTPSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)
        email= serializer.validated_data['email']  
        mail_res = send_otp(email)
        return Response(mail_res)
            


class LoginAPI(APIView):
    def post(self, request):
        serializer = Loginserializers(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            email = serializer.validated_data['email']
            password = serializer.validated_data['password']
            user = authenticate(email=email, password=password)
            if user is not None:
                refresh  =  RefreshToken.for_user(user)
                return Response({
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                })
            else:
                raise AuthenticationFailed("Incorrect email or password")
        except AuthenticationFailed as e:
            return Response({"detail": str(e)}, status=status.HTTP_401_UNAUTHORIZED)
        



class ChangePassword(APIView):
    permission_classes = [IsAuthenticated]
    def patch(self, request):
        try:
            serializer = ChangePasswordSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = request.user
            old_password = serializer.data.get('old_password')
            new_password = serializer.data.get('new_password')

            if old_password == new_password:
                return Response({'error': 'Old and new passwords cannot be the same.'}, status=status.HTTP_200_OK)
            if user.check_password(old_password):
                user.set_password(new_password)
                user.save()
                return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"msg": str(e)}, status=status.HTTP_400_BAD_REQUEST)                                                                                                                                                                                         
        



class RequestResetPassword(APIView):
    def post(self, request):
        serializer = RequestResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        char = string.ascii_letters +string.digits
        otp = "".join(random.choice(char) for _ in range(6))
        user = User.objects.get(email=serializer.validated_data['email'])
        
        if user.is_active is True:
            subject = "One-Time Password (OTP) for Reset Password"
            messege = f"Dear {user.full_name},\n\nYour OTP is {otp}\nThank you for choosing our service. To ensure the security of your account and to complete the user verification process, we have generated a one-time password (OTP) for you.\nPlease enter this OTP on our website or application to verify your account. This OTP is valid for a Three miuntes, so we recommend completing the verification process as soon as possible.\nIf you did not request this OTP or have any concerns about your account's security, please contact our support team immediately.\nThank you for trusting us with your user verification.\nWe look forward to providing you with a secure and seamless experience.\n\n\n\nSincerely,\n(Team RK) "
            email_from = settings.EMAIL_FROM
            send_mail(subject, messege, email_from, [user])
            OTP_Master.objects.create(email=user, otp=otp)
            return Response({'message': 'Your One-Time Password (OTP) has been sent to Your Email.'}, status=status.HTTP_200_OK)
        return Response({'message': 'User Not active.'}, status=status.HTTP_200_OK)



class ResetPasswordAPI(APIView):
    def patch(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp = serializer.validated_data['otp']
        new_password = serializer.validated_data['new_password']
        
        try:
            user = User.objects.get(email=email)
            otp_instance = OTP_Master.objects.filter(email=user).last()
            if otp_instance and otp_instance.is_valid() and otp_instance.otp == otp:
                user.set_password(new_password)
                user.save()
                return Response({"msg": "New Password Created Successfully"})
            elif otp_instance and not otp_instance.is_valid():
                return Response({"msg": "Your OTP has expired. Please Resend."}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"msg": "Wrong OTP. Please try again"}, status=status.HTTP_400_BAD_REQUEST)
        except User.DoesNotExist:
            return Response({"msg": "User not found."}, status=status.HTTP_404_NOT_FOUND)
    