from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from keychain.models import KeyChain, App
from keychain.lib import *
from hashlib import sha256
from django.core.files.storage import FileSystemStorage
from pathlib import Path
import os

class Command(BaseCommand):
    def handle(self, *args, **options):
        mypath = Path().absolute()
        # print('Absolute path : {}'.format(mypath))
        users = User.objects.all()
        for user in users:
            userId = create_hmac_sha256_signature(generate_derivation(masterPass="55555",seed="65C6AEdf045CFbb9d3D818CC7a708d6c", num= sumOrd(user.username) // len(user.username)), user.id)
            keychain = KeyChain.objects.get(owner=userId)
            apps = App.objects.filter(keychain__pk=keychain.id)
            for app in apps:
                if not app.integrity_ckeck == sha256(app.password.encode()).hexdigest():
                    folder = os.path.join("keychain/dumps/" + str(keychain.id) + "/", str(app.id))
                    try:
                        print(folder)
                        # f=open(folder + "/dump.txt","r")
                        # contents =f.read()
                        print(app.password)
                        # app.password = contents
                        # print(app.password)
                        # app.save()
                        # f.close() 
                    except:
                        print("does not have a available dump")
                        
        
        