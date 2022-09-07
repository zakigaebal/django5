# authentication > api > serializers.py
from rest_framework import serializers
from django.contrib.auth.models import User
from .views import *

class RegistrationSerializer(serializers.ModelSerializer):
    
    password = serializers.CharField(
        max_length = 128,
        min_length = 8,
        write_only = True
    )
    
    token = serializers.CharField(max_length=255, read_only=True)
    
    class Meta:
        model = User
        fields = [
            'email', 
            'username',
            'phone_number',
            'password',
            'token'
            ]
        
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)​
    
    
    
    
class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    # 1.
    username = serializers.CharField(max_length=255, read_only=True)
    password = serializers.CharField(max_length=128, write_only=True)
    last_login = serializers.CharField(max_length=255, read_only=True)
    
    # 2.
    def validate(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        
        # 3.
        if email is None:
            raise serializers.ValidationError(
                'An email address is required to log in.'
            )
        
        if password is None:
            raise serializers.ValidationError(
                'A password is required to log in.'
            )
        
        # 4.
        user = authenticate(username=email, password=password)
        
        # 5.
        if user is None:
            raise serializers.ValidationError(
                'A user with this email and password was not found'
            )
        
        if not user.is_active:
            raise serializers.ValidationError(
                'This user has been deactivated.'
            )
        
        # 6.
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])
        
        # 7.
        return {
            'email': user.email,
            'username': user.username,
            'last_login': user.last_login
        }