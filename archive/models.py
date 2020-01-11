from django.db import models

class ActiveIP(models.Model):
	ip = models.CharField(max_length=100)
	downloads = models.IntegerField(default=0)
	time = models.BigIntegerField(default=0)

	def __str__(self):
		return self.ip