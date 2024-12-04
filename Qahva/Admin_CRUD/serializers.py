from rest_framework import serializers
from .models import User
from rest_framework.response import Response
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema


class UserCreateSerializer(serializers.ModelSerializer):
    passwordConfirm = serializers.CharField(write_only=True, required=True, help_text="Password confirmation")
    image = serializers.ImageField(required=False, help_text="Profile image (optional)")

    class Meta:
        model = User
        fields = ['name', 'email', 'password', 'passwordConfirm', 'image']

    def validate(self, data):
        # Validate if passwords match
        if data['password'] != data['passwordConfirm']:
            raise serializers.ValidationError({"passwordConfirm": "Passwords must match."})
        return data

    def create(self, validated_data):
        validated_data.pop('passwordConfirm')  # Remove password confirmation before saving
        user = User.objects.create_user(**validated_data)  # Create user with validated data
        return user




@swagger_auto_schema(
    operation_description="Create a new user with a profile image (optional).",
    request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'name': openapi.Schema(type=openapi.TYPE_STRING, description="User's name"),
            'email': openapi.Schema(type=openapi.TYPE_STRING, description="User's email (must be unique)"),
            'password': openapi.Schema(type=openapi.TYPE_STRING, description="Password"),
            'passwordConfirm': openapi.Schema(type=openapi.TYPE_STRING, description="Password confirmation"),
            'image': openapi.Schema(type=openapi.TYPE_FILE, description="Profile image (optional)"),
        },
        required=['name', 'email', 'password', 'passwordConfirm']  # Specify required fields
    ),
    responses={
        201: openapi.Response("User created successfully"),
        400: openapi.Response("Bad request. Validation failed."),
    }
)
def post(self, request, *args, **kwargs):
    # Example of creating a user through the serializer
    serializer = UserCreateSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        return Response({"status": "User created successfully!"}, status=201)
    return Response(serializer.errors, status=400)




class UserSerializer(serializers.ModelSerializer):
    image = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ['id', 'name', 'email', 'image', 'created_at', 'updated_at', 'updates']

    def get_image(self, obj):
        return f"profileImage/{obj.image.name}" if obj.image else None



class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['name', 'email', 'password']
    
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            if attr == 'password':  # Хэширование пароля
                instance.set_password(value)
            else:
                setattr(instance, attr, value)
        instance.updates += 1
        instance.save()
        return instance


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    password = serializers.CharField(write_only=True)