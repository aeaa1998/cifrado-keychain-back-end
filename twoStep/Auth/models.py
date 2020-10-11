from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class UserDevice(models.Model):
    number = models.IntegerField()
    otp_counter = models.IntegerField()
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="devices"
    )
    created_at = models.DateTimeField(auto_now_add=True, blank=True)
    updated_at = models.DateTimeField(auto_now_add=True, blank=True)
    class Meta:
        db_table = 'user_devices'