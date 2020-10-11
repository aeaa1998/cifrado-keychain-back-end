from .serializers import UserSerializer
from django.core import serializers
from collections.abc import Iterable
from django.db.models.query import QuerySet
from django.core.exceptions import ObjectDoesNotExist

def jwt_response_payload_handler(token, user=None, request=None):
    return {
        'token': token,
        'payload': UserSerializer(user, context={'request': request}).data
    }
