from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone


CHOICE = (('admin', 'admin'), ('manager', 'manager'), ('employee', 'employee'), ('seller', 'seller'), ('user', 'user'), ('shipper', 'shipper'))







class CustomUserBaseManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('User Must Have EMAIL ID')
        email = self.normalize_email(email)
        user = self.model(email = email, **extra_fields)
        user.set_password(password)
        user.save(self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields): #def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True) #is_superuser
        extra_fields.setdefault('is_active', True)
        extra_fields.setdefault('role', 'admin')

        if extra_fields.get('is_staff') is not True:
            raise ValueError('is_staff must be TRUE')
        
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('is_superuser must be TRUE')
        
        if extra_fields.get('is_active') is not True:
            raise ValueError('is_active must be TRUE')
        
        return self.create_user(email, password, **extra_fields)
    


class User(AbstractBaseUser, PermissionsMixin):
    role = models.CharField(max_length=50, choices=CHOICE, default='user')
    full_name = models.CharField(max_length=200, null=True)
    email = models.EmailField(unique=True, max_length=300)
    mobile_number = models.CharField(max_length=14, unique=True, null=True)
    dob = models.DateField(null = True)
    address = models.TextField(null=True)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    # is_admin = models.BooleanField(default=False)
    objects = CustomUserBaseManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email
    




class OTP_Master(models.Model):
    email = models.ForeignKey(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        now = timezone.now()
        return (now-self.created_at).total_seconds() <= 180
    
