from django.conf import settings
from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.db import models

class  Userprofile(models.Model) :

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    type = models.SmallIntegerField()
    created_date = models.DateTimeField(default=timezone.now)
    updated_date = models.DateTimeField(blank=True, null=True)

    def publish(self):
        self.updated_date = timezone.now()
        self.save()

    #def __str__(self):
        #return self.title