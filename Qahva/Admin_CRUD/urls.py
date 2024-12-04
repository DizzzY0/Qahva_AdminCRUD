from django.urls import path
from .views import (
    UserListAPIView,
    UserCreateAPIView,
    UserUpdateAPIView,
    UserProfileImageAPIView,
    LoginAPIView,
    DeleteUserAPIView,
    RetrieveUserAPIView,   
    LogoutAPIView,
)

urlpatterns = [
    path('users/<uuid:userID>/', RetrieveUserAPIView.as_view(), name='retrieve-user'),
    path('users/', UserCreateAPIView.as_view(), name='user-create'),
    path('users/delete/', DeleteUserAPIView.as_view(), name='delete-user'),
    path('users/all/', UserListAPIView.as_view(), name='user-list'),
    path('users/update/<uuid:userID>/', UserUpdateAPIView.as_view(), name='update-user'),
    path('users/images/', UserProfileImageAPIView.as_view(), name='user-image'),
    path('sessions/login', LoginAPIView.as_view(), name='login'),
    path('sessions/logout', LogoutAPIView.as_view(), name='logout'),
]

