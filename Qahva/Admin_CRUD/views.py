from tokenize import TokenError
from rest_framework import generics, status
from rest_framework.response import Response
from .models import User
from .serializers import (
    UserSerializer,
    UserCreateSerializer,
    UserUpdateSerializer,
    UserLoginSerializer,
)
from rest_framework.views import APIView
from django.http import FileResponse
from django.conf import settings
import os
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.authentication import JWTAuthentication




class UserListAPIView(generics.ListAPIView):
    """Список всех пользователей."""
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny] 


class UserCreateAPIView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [AllowAny]
    @swagger_auto_schema(
        request_body=UserCreateSerializer,
        responses={201: "User created", 400: "Bad Request"}
    )
    def post(self, request, *args, **kwargs):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            response_data = {
                "status": "OK",
                "user": {
                    "id": str(user.id),
                    "name": user.name,
                    "email": user.email,
                    "image": user.image.url if user.image else None,
                    "createdAt": user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                    "updatedAt": user.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                    "__v": user.updates,
                }
            }
            return Response(response_data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class DeleteUserAPIView(APIView):
    """
    Удаление пользователя по ID.
    """

    @swagger_auto_schema(
        operation_description="Удалить пользователя по ID",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'userId': openapi.Schema(type=openapi.TYPE_STRING, description="ID пользователя"),
            },
            required=['userId'],
        ),
        responses={
            200: openapi.Response(
                description="Пользователь успешно удалён",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "message": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            400: openapi.Response(
                description="Некорректный запрос",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "error": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
            404: openapi.Response(
                description="Пользователь не найден",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "error": openapi.Schema(type=openapi.TYPE_STRING),
                    },
                ),
            ),
        },
    )
    def delete(self, request, *args, **kwargs):
        user_id = request.data.get('userId')

        if not user_id:
            return Response({"error": "UserId is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = User.objects.get(id=user_id)
            user.delete()
            return Response({"message": "User has been successfully deleted"}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class RetrieveUserAPIView(APIView):
    """
    Получить данные пользователя по userID.
    """
    authentication_classes = [JWTAuthentication]  # Используем JWT-аутентификацию
    permission_classes = [IsAuthenticated]  # Требуется аутентификация

    @swagger_auto_schema(
        operation_description="Получить информацию о пользователе по его ID",
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Bearer accessToken",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description="Успешный запрос",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "status": openapi.Schema(type=openapi.TYPE_STRING),
                        "user": openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                "userId": openapi.Schema(type=openapi.TYPE_STRING),
                                "name": openapi.Schema(type=openapi.TYPE_STRING),
                                "email": openapi.Schema(type=openapi.TYPE_STRING),
                                "image": openapi.Schema(type=openapi.TYPE_STRING),
                                "createdAt": openapi.Schema(type=openapi.TYPE_STRING),
                                "updatedAt": openapi.Schema(type=openapi.TYPE_STRING),
                            },
                        ),
                    },
                ),
            ),
            401: openapi.Response(description="Unauthorized"),
            404: openapi.Response(description="Пользователь не найден"),
        }
    )
    def get(self, request, userID, *args, **kwargs):
        try:
            # Получение пользователя по ID
            user = User.objects.get(id=userID)
            user_data = {
                "userId": str(user.id),
                "name": user.name,
                "email": user.email,
                "image": user.image.url if user.image else None,
                "createdAt": user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                "updatedAt": user.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
            }
            return Response({"status": "OK", "user": user_data}, status=status.HTTP_200_OK)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)


class UserUpdateAPIView(APIView):
    """
    Обновление пользователя по userID.
    """
    permission_classes = [AllowAny] 
    @swagger_auto_schema(
    operation_description="Обновить данные пользователя",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            "name": openapi.Schema(type=openapi.TYPE_STRING, description="Новое имя"),
            "email": openapi.Schema(type=openapi.TYPE_STRING, description="Новый email"),
            "password": openapi.Schema(type=openapi.TYPE_STRING, description="Новый пароль"),
        },
        required=["name", "email", "password"]
    ),
    responses={
        200: openapi.Response(description="Успешно обновлено"),
        400: openapi.Response(description="Ошибка запроса"),
        404: openapi.Response(description="Пользователь не найден"),
    }
    )

    def put(self, request, userID, *args, **kwargs):
        try:
            user = User.objects.get(id=userID)
        except User.DoesNotExist:
            return Response({"error": "User not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = UserUpdateSerializer(user, data=request.data, partial=True)  # partial=True позволяет обновлять только указанные поля
        if serializer.is_valid():
            serializer.save()
            return Response({
                "name": serializer.data.get('name'),
                "email": serializer.data.get('email'),
                "password": "Updated",  # Пароль не возвращается по безопасности, но обновляется
                "createdAt": user.created_at.strftime('%Y-%m-%d %H:%M:%S'),
                "updatedAt": user.updated_at.strftime('%Y-%m-%d %H:%M:%S'),
                "__v": user.updates,  # Количество изменений
                "_id": str(user.id)
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class UserProfileImageAPIView(APIView):
    parser_classes = [MultiPartParser, FormParser]  # Указываем парсеры для обработки multipart/form-data

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'url',
                openapi.IN_FORM,  # Указываем, что это поле формы
                description="Path to the user image (e.g., 'user_images/image_name.jpg')",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: "Image retrieved successfully",
            400: "Bad Request",
            404: "Image not found"
        }
    )
    def post(self, request, *args, **kwargs):
        image_url = request.data.get("url")  # Получаем URL изображения из данных формы
        if not image_url:
            return Response({"error": "Image URL is required"}, status=400)
        
        # Полный путь к изображению
        image_path = os.path.join(settings.MEDIA_ROOT, image_url.strip("/"))
        
        # Проверяем, существует ли файл
        if not os.path.exists(image_path):
            return Response({"error": "Image not found"}, status=404)
        
        # Возвращаем файл
        return FileResponse(open(image_path, 'rb'), content_type='image/jpeg')
    


class LoginAPIView(APIView):
    """
    API для входа пользователя и получения токенов.
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        request_body=UserLoginSerializer,
        responses={
            200: openapi.Response(
                description="Успешный логин",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "user": openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                "name": openapi.Schema(type=openapi.TYPE_STRING, description="Имя пользователя"),
                                "email": openapi.Schema(type=openapi.TYPE_STRING, description="Email пользователя"),
                            },
                        ),
                        "tokens": openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                "accessToken": openapi.Schema(type=openapi.TYPE_STRING, description="Access токен"),
                                "refreshToken": openapi.Schema(type=openapi.TYPE_STRING, description="Refresh токен"),
                            },
                        ),
                    },
                ),
            ),
            400: "Bad Request",
            401: "Unauthorized",
        }
    )
    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data["email"]
            password = serializer.validated_data["password"]

            user = authenticate(email=email, password=password)
            if user:
                # Генерация токенов
                refresh = RefreshToken.for_user(user)
                access = refresh.access_token

                return Response(
                    {
                        "user": {
                            "name": user.name,
                            "email": user.email,
                        },
                        "tokens": {
                            "accessToken": str(access),
                            "refreshToken": str(refresh),
                        },
                    },
                    status=status.HTTP_200_OK,
                )
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LogoutAPIView(APIView):
    """
    Logout пользователя и аннулирование токенов.
    """
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Удаление токенов и завершение сессии.",
        manual_parameters=[
            openapi.Parameter(
                'Authorization',
                openapi.IN_HEADER,
                description="Bearer accessToken",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                'x-refresh',
                openapi.IN_HEADER,
                description="Refresh токен для завершения сессии",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            200: openapi.Response(
                description="Сессия завершена",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "accessToken": openapi.Schema(type=openapi.TYPE_STRING, description="Обнулённый токен"),
                        "refreshToken": openapi.Schema(type=openapi.TYPE_STRING, description="Обнулённый токен"),
                    },
                ),
            ),
            400: "Bad Request",
            401: "Unauthorized",
        },
    )
    def delete(self, request, *args, **kwargs):
        refresh_token = request.headers.get('x-refresh')
        if not refresh_token:
            return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()  # Добавляем токен в "чёрный список"
            return Response({"accessToken": None, "refreshToken": None}, status=status.HTTP_200_OK)
        except TokenError as e:
        # Если проблема связана с токеном
            return Response({"error": f"Token error: {str(e)}"}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
        # Если возникла другая ошибка
            return Response({"error": f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)