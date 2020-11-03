from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class KeyChain(models.Model):
    owner = models.TextField()
    otp_counter = models.IntegerField()
    key = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now_add=True, blank=True)
    class Meta:
        db_table = 'keychains'

class App(models.Model):
    name = models.TextField()
    password = models.TextField()
    integrity_ckeck = models.TextField()
    keychain = models.ForeignKey(
        KeyChain,
        on_delete=models.CASCADE,
        related_name="apps"
    )