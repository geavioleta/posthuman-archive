# Generated by Django 3.0 on 2019-12-07 18:43

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='ActiveIP',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip', models.CharField(max_length=500)),
                ('downloads', models.IntegerField(default=0)),
                ('time', models.BigIntegerField(default=1575744226)),
            ],
        ),
    ]