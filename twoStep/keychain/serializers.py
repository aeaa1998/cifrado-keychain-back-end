 
from rest_framework import serializers
from .models import KeyChain, App

class KeyChainSerializer(serializers.ModelSerializer):
    class Meta:
        model = KeyChain
        fields = '__all__'

class AppSerializer(serializers.ModelSerializer):
    class Meta:
        model = App
        fields = ['id', 'name', 'password']

class AppCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = App
        fields = '__all__'