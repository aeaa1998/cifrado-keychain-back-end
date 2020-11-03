from django.shortcuts import render
from rest_framework import routers, serializers, viewsets
from rest_framework.response import Response
from rest_framework.request import Request
import json
import base64
from datetime import *
import pyotp
from twilio.rest import Client
from django.http import HttpResponse
from .lib import *
from rest_framework.decorators import action
from .serializers import AppSerializer, AppCreateSerializer,KeyChainSerializer
from hashlib import sha256
# from serializers import 
from Auth.models import UserDevice
from .models import KeyChain, App
# Create your views here.
class generateKey:
    @staticmethod
    def returnValue(keychain):
        # Aca tenemos que ver que onda
        return str(keychain.owner) + str(datetime.date(datetime.now())) + keychain.key


class KeyChainView(viewsets.ModelViewSet):
    queryset = KeyChain.objects.all()
    serializer_class = KeyChainSerializer

    @action(detail=False, url_path='app', methods=['get'])
    def getUserKeychain(self, request):
        userId = create_hmac_sha256_signature(generate_derivation(masterPass="55555",seed="65C6AEdf045CFbb9d3D818CC7a708d6c", num= sumOrd(request.user.username) // len(request.user.username)), request.user.id)
        keychain = self.queryset.get(owner=userId)
        raw_apps = App.objects.filter(keychain__pk=keychain.id)
        apps = []
        for app in raw_apps:
            app.password = m_decrypt(app.password, keychain.key)
            apps.append(app)
        serializer_context = {'request': Request(request._request)}
        return Response(AppSerializer(apps, many=True, context=serializer_context).data, 200)
    
    @action(detail=False, url_path='app/create', methods=['post'])
    def setApp(self, request):
        userId = create_hmac_sha256_signature(generate_derivation(masterPass="55555",seed="65C6AEdf045CFbb9d3D818CC7a708d6c", num= sumOrd(request.user.username) // len(request.user.username)), request.user.id)
        keychain = self.queryset.get(owner=userId)
        if App.objects.filter(keychain__pk=keychain.id).filter(name=request.data['name']).exists():
            return Response("El nombre ya ya sido usado", 404)
    
        # request.data._mutable = True
        request.data['keychain'] = keychain.id
        request.data['password'] = m_encrypt(request.data["password"], keychain.key.encode())
        request.data['integrity_ckeck'] = sha256(request.data['password'].encode()).hexdigest()
        # request.data._mutable = False
        serializer = AppCreateSerializer(data=request.data) 
        if serializer.is_valid():
            serializer.save()
            app = App.objects.get(pk=serializer.data['id'])
            serializer_context = {'request': Request(request._request)}
            return Response(AppSerializer(app, context=serializer_context).data, 200)
			# return Response(data=serializer.data, status=200)
        else:
            return Response(serializer.errors, status=400)


    # @action(detail=False, url_path='app/(?P<pk>\d+)/update', methods=['put'])
    # def updateApp(self, request, pk):
    #     userId = create_hmac_sha256_signature(generate_derivation(masterPass="55555",seed="65C6AEdf045CFbb9d3D818CC7a708d6c", num= sumOrd(request.user.username) // len(request.user.username)), request.user.id)
    #     keychain = self.queryset.get(owner=userId)
    #     app = App.objects.filter(keychain__pk=keychain.id).get(pk=pk)
    #     if app.integrity_ckeck != sha256(app.password.encode()).hexdigest():
    #         return Response("Password has been altered", 400)
    #     app.password = m_encrypt(request.data["password"], keychain.key.encode())
    #     app.integrity_ckeck = sha256(app.password.encode()).hexdigest()
    #     app.save()
    #     serializer_context = {'request': Request(request._request)}
    #     return Response(AppSerializer(app, context=serializer_context).data, 200)

    @action(detail=False, url_path='app/(?P<pk>\d+)', methods=['get'])
    def getPassword(self, request, pk):
        userId = create_hmac_sha256_signature(generate_derivation(masterPass="55555",seed="65C6AEdf045CFbb9d3D818CC7a708d6c", num= sumOrd(request.user.username) // len(request.user.username)), request.user.id)
        keychain = self.queryset.get(owner=userId)
        app = App.objects.filter(keychain__pk=keychain.id).get(pk=pk)
        if app.integrity_ckeck == sha256(app.password.encode()).hexdigest():
            return Response(m_decrypt(app.password, keychain.key), 200)
        else:
            return Response("Password has been altered", 400)

    
    @action(detail=False, url_path='otp/(?P<pk>\d+)', methods=['get'])
    def getCode(self, request, pk):
        userId = create_hmac_sha256_signature(generate_derivation(masterPass="55555",seed="65C6AEdf045CFbb9d3D818CC7a708d6c", num= sumOrd(request.user.username) // len(request.user.username)), request.user.id)
        keychain = self.queryset.get(owner=userId)
        keychain.otp_counter +=1
        keychain.save()
        device = UserDevice.objects.get(pk=pk)
        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(keychain).encode())
        OTP = pyotp.HOTP(key)
        account_sid = 'ACc2525a5beaaf32d91f9eb14969f3831e'
        auth_token = '83b537264f0453ab5cf6e0f1060c6020'
        client = Client(account_sid, auth_token)
        otpToken = OTP.at(keychain.otp_counter)
        message = client.messages.create(
                              body="Tu Codigo para ingresar resetar la contraseña " + otpToken,
                              from_='+18152494556',
                              to='+502' + str(device.number)
                          )
        return Response({"OTP": otpToken}, status=200)


    @action(detail=False, url_path='app/(?P<pk>\d+)/reset', methods=['put'])
    def updateApp(self, request, pk):
        userId = create_hmac_sha256_signature(generate_derivation(masterPass="55555",seed="65C6AEdf045CFbb9d3D818CC7a708d6c", num= sumOrd(request.user.username) // len(request.user.username)), request.user.id)
        keychain = self.queryset.get(owner=userId)
        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(keychain).encode())
        OTP = pyotp.HOTP(key)
        if OTP.verify(request.data['otp'], keychain.otp_counter):
            app = App.objects.filter(keychain__pk=keychain.id).get(pk=pk)
            app.password = m_encrypt(request.data["password"], keychain.key.encode())
            app.integrity_ckeck = sha256(app.password.encode()).hexdigest()
            app.save()
            keychain.otp_counter +=1
            keychain.save()
            return Response("password reseted", 200)
        else:
            return HttpResponse(json.dumps({"error" : "OTP invalido"}), 404)

    @action(detail=False, url_path='app/(?P<pk>\d+)/delete', methods=['post'])
    def deleteApp(self, request, pk):
        userId = create_hmac_sha256_signature(generate_derivation(masterPass="55555",seed="65C6AEdf045CFbb9d3D818CC7a708d6c", num= sumOrd(request.user.username) // len(request.user.username)), request.user.id)
        keychain = self.queryset.get(owner=userId)
        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(keychain).encode())
        OTP = pyotp.HOTP(key)
        if OTP.verify(request.data['otp'], keychain.otp_counter):
            app = App.objects.filter(keychain__pk=keychain.id).filter(pk=pk).delete()
            keychain.otp_counter +=1
            keychain.save()
            return Response("App Deleted", 200)
        else:
            return HttpResponse(json.dumps({"error" : "OTP invalido"}), 404)

