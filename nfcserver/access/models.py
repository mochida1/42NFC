from django.db import models

class Record(models.Model):
    login = models.CharField(max_length=50)
    is_entry = models.BooleanField()
    timestamp = models.DateTimeField()
