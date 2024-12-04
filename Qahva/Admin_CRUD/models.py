import uuid
import os
from datetime import datetime
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db import models


def user_image_upload_path(instance, filename):
    """Формирование пути для сохранения изображений пользователя."""
    ext = filename.split('.')[-1]
    filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{instance.id}.{ext}"
    return os.path.join('user_images', filename)


class UserManager(BaseUserManager):
    """Менеджер пользователей."""

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field is required.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)  # Хэшируем пароль
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser):
    """Кастомная модель пользователя."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=255)
    password = models.CharField(max_length=128)
    image = models.ImageField(upload_to=user_image_upload_path, blank=True, null=True)
    updates = models.PositiveIntegerField(default=0)  # Новое поле для подсчёта обновлений
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['name']

    def __str__(self):
        return self.email
