from django_cron import CronJobBase, Schedule
from django.contrib.auth.models import User
from keychain.models import KeyChain, App
from keychain.lib import *
from hashlib import sha256
from django.core.files.storage import FileSystemStorage
from pathlib import Path
import os

class CheckIntegrity(CronJobBase):
    RUN_EVERY_MINS = 1 # every minute

    schedule = Schedule(run_every_mins=RUN_EVERY_MINS)
    code = 'keychain.checkintegrity'    # a unique code

    def do(self):
        print("Init")
        users = User.objects.all()
        for user in users:
            userId = create_hmac_sha256_signature(generate_derivation(masterPass="55555",seed="65C6AEdf045CFbb9d3D818CC7a708d6c", num= sumOrd(user.username) // len(user.username)), user.id)
            keychain = KeyChain.objects.get(owner=userId)
            apps = App.objects.filter(keychain__pk=keychain.id)
            for app in apps:
                if not app.integrity_ckeck == sha256(app.password.encode()).hexdigest():
                    mypath = Path().absolute()
                    print('Absolute path : {}'.format(mypath))

                    
                    try:
                        folder = os.path.join(str(mypath) + "/django/twoStepVerification/twoStep/keychain/dumps/" + str(keychain.id) + "/", str(app.id))
                        f=open(folder + "/dump.txt","r")
                        contents =f.read()
                        app.password = contents
                        app.save()
                        f.close() 
                        print("Success")
                    except Exception as e:
                        print("does not have a available dump")
                        print(str(e))
                        print(folder)