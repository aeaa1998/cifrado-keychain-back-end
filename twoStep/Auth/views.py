import json
from django.shortcuts import render
from django.contrib.auth.hashers import check_password
from rest_framework.response import Response
from rest_framework.request import Request
import pyotp
import base64
from datetime import datetime
from rest_framework.decorators import action
from django.http import HttpResponse
from rest_framework import status
from django.db import IntegrityError
from rest_framework import routers, serializers, viewsets
from .serializers import UserSerializer
from rest_framework_jwt.settings import api_settings
from rest_framework.views import APIView
from .jwtSerializers import (
    JSONWebTokenSerializer, RefreshJSONWebTokenSerializer
)
from twilio.rest import Client
jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER

jwt_response_payload_handler = api_settings.JWT_RESPONSE_PAYLOAD_HANDLER
from django.contrib.auth.models import User
from .models import UserDevice
from keychain.models import KeyChain
from keychain.lib import *
from django.contrib.auth import authenticate

class generateKey:
    @staticmethod
    def returnValue(phone):
        # Aca tenemos que ver que onda
        return str(phone) + str(datetime.date(datetime.now())) + "Some Random Secret Key"

# Create your views here.
class AuthView(viewsets.ModelViewSet):
    permission_classes = ()
    serializer_class = UserSerializer
    queryset = User.objects.all()

    @action(detail=False, url_path='verify', methods=['post'])
    def verifyUser(self, request):
        username = request.data['username']
        password = request.data['password']
        try:
            user =  User.objects.get(username=username)
            if check_password(password, user.password):
                phone = UserDevice.objects.get(user__username=username) 
                return Response(phone.id, 200)
            else:
                return Response(password, 401)
        except (Exception) as e:
            return Response("Invalid credentials", 401)

    @action(detail=False, url_path='otp/(?P<pk>\d+)', methods=['get'])
    def getTwoToken(self, request, pk):
        phone = UserDevice.objects.get(pk=pk) 
        phone.otp_counter+=1
        phone.save()
        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(phone.number).encode())
        OTP = pyotp.HOTP(key)
        account_sid = 'ACc2525a5beaaf32d91f9eb14969f3831e'
        auth_token = 'cce370de5f5e48118a03522bf8bb04bd'
        client = Client(account_sid, auth_token)
        otpToken = OTP.at(phone.otp_counter)
        message = client.messages.create(
                              body="Tu Codigo para ingresar sesión " + otpToken,
                              from_='+18152494556',
                              to='+502' + str(phone.number)
                          )
        return Response({"OTP": otpToken}, status=200)


    def login(self, request):
        username = request.data['username']
        password = request.data['password']
        phone_pk = request.data['phone_pk']
        otp = request.data['otp']
        phone = UserDevice.objects.get(pk=phone_pk)
        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(phone.number).encode())
        OTP = pyotp.HOTP(key)
        if OTP.verify(request.data['otp'], phone.otp_counter):
            user = authenticate(username=username, password=password)
            # user = None
            if user:
                payload = jwt_payload_handler(user)
                serializer_context = {'request': Request(request._request)}
                return HttpResponse(json.dumps({'token': jwt_encode_handler(payload),'user': UserSerializer(user, context=serializer_context).data}), 200)
            else:
                return HttpResponse(json.dumps({"error" : "Credenciales invalidas"}), 401)
        else:
            return HttpResponse(json.dumps({"error" : "OTP invalido"}), 401)



class RegisterView(viewsets.ModelViewSet):
    permission_classes = ()
    queryset = User.objects.all()
    serializer_class = UserSerializer

    def create(self, request):
        try:
            first_name = request.data['first_name']
            email = request.data['email']
            username = request.data['username']
            phone = request.data['phone_number']
            password = request.data['password']
            user = User.objects.create_user(username, email, password)
            user.first_name = first_name
            user.save()
            phone = UserDevice(number=phone, user=user, otp_counter=0)
            phone.save()

            userId = create_hmac_sha256_signature(generate_derivation(masterPass="55555",seed="65C6AEdf045CFbb9d3D818CC7a708d6c", num= sumOrd(username) // len(username)), user.id)
            keychain = KeyChain(owner=userId, key=generate_random_string(16), otp_counter=0)
            keychain.save()

            serializer_context = {'request': Request(request._request)}
            return Response(UserSerializer(user, context=serializer_context).data)
        except (IntegrityError) as e:
            if (str(e).find("username") > -1):
                return Response({"errorMessage" : "Ese usuario ya ha sido tomado"}, 412)
            else:
                return Response({"errorMessage" : "Ese correo ya ha sido tomado"}, 412)
        except (KeyError) as e:
            return HttpResponse(json.dumps({"errorMessage" : "missing_fields"}), 412)
        except (User.DoesNotExist):
            return HttpResponse(json.dumps({"errorMessage" : "Error al crear el ususario"}), 404)
        except (Exception) as e:
            return Response({"errorMessage" : "Ese usuario ya ha sido tomado"}, 412)


class JSONWebTokenAPIView(APIView):
    """
    Base API View that various JWT interactions inherit from.
    """
    permission_classes = ()
    authentication_classes = ()

    def get_serializer_context(self):
        """
        Extra context provided to the serializer class.
        """
        return {
            'request': self.request,
            'view': self,
        }

    def get_serializer_class(self):
        """
        Return the class to use for the serializer.
        Defaults to using `self.serializer_class`.
        You may want to override this if you need to provide different
        serializations depending on the incoming request.
        (Eg. admins get full serialization, others get basic serialization)
        """
        assert self.serializer_class is not None, (
            "'%s' should either include a `serializer_class` attribute, "
            "or override the `get_serializer_class()` method."
            % self.__class__.__name__)
        return self.serializer_class

    def get_serializer(self, *args, **kwargs):
        """
        Return the serializer instance that should be used for validating and
        deserializing input, and for serializing output.
        """
        serializer_class = self.get_serializer_class()
        kwargs['context'] = self.get_serializer_context()
        return serializer_class(*args, **kwargs)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user = serializer.object.get('user') or request.user
            token = serializer.object.get('token')
            response_data = jwt_response_payload_handler(token, user, request)
            response = Response(response_data)
            if api_settings.JWT_AUTH_COOKIE:
                expiration = (datetime.utcnow() +
                              api_settings.JWT_EXPIRATION_DELTA)
                response.set_cookie(api_settings.JWT_AUTH_COOKIE,
                                    token,
                                    expires=expiration,
                                    httponly=True)
            return response

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ObtainJSONWebToken(JSONWebTokenAPIView):
    """
    API View that receives a POST with a user's username and password.

    Returns a JSON Web Token that can be used for authenticated requests.
    """
    serializer_class = JSONWebTokenSerializer




class RefreshJSONWebToken(JSONWebTokenAPIView):
    """
    API View that returns a refreshed token (with new expiration) based on
    existing token

    If 'orig_iat' field (original issued-at-time) is found, will first check
    if it's within expiration window, then copy it to the new token
    """
    serializer_class = RefreshJSONWebTokenSerializer


# obtain_jwt_token = ObtainJSONWebToken.as_view()
refresh_jwt_token = RefreshJSONWebToken.as_view()
# obtain_jwt_token = ObtainJSONWebToken.as_view()

