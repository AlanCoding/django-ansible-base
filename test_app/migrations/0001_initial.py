# Generated by Django 4.2.8 on 2024-01-26 11:03

import uuid

from django.conf import settings
import django.contrib.auth.models
import django.contrib.auth.validators
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('password', models.CharField(max_length=128, verbose_name='password')),
                ('last_login', models.DateTimeField(blank=True, null=True, verbose_name='last login')),
                ('is_superuser', models.BooleanField(default=False, help_text='Designates that this user has all permissions without explicitly assigning them.', verbose_name='superuser status')),
                ('username', models.CharField(error_messages={'unique': 'A user with that username already exists.'}, help_text='Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.', max_length=150, unique=True, validators=[django.contrib.auth.validators.UnicodeUsernameValidator()], verbose_name='username')),
                ('first_name', models.CharField(blank=True, max_length=150, verbose_name='first name')),
                ('last_name', models.CharField(blank=True, max_length=150, verbose_name='last name')),
                ('email', models.EmailField(blank=True, max_length=254, verbose_name='email address')),
                ('is_staff', models.BooleanField(default=False, help_text='Designates whether the user can log into this admin site.', verbose_name='staff status')),
                ('is_active', models.BooleanField(default=True, help_text='Designates whether this user should be treated as active. Unselect this instead of deleting accounts.', verbose_name='active')),
                ('date_joined', models.DateTimeField(default=django.utils.timezone.now, verbose_name='date joined')),
                ('created_on', models.DateTimeField(default=None, editable=False, help_text='The date/time this resource was created')),
                ('modified_on', models.DateTimeField(default=None, editable=False, help_text='The date/time this resource was created')),
                ('created_by', models.ForeignKey(default=None, editable=False, help_text='The user who created this resource', null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='%(app_label)s_%(class)s_created+', to=settings.AUTH_USER_MODEL)),
                ('groups', models.ManyToManyField(blank=True, help_text='The groups this user belongs to. A user will get all permissions granted to each of their groups.', related_name='user_set', related_query_name='user', to='auth.group', verbose_name='groups')),
                ('modified_by', models.ForeignKey(default=None, editable=False, help_text='The user who last modified this resource', null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='%(app_label)s_%(class)s_modified+', to=settings.AUTH_USER_MODEL)),
                ('user_permissions', models.ManyToManyField(blank=True, help_text='Specific permissions for this user.', related_name='user_set', related_query_name='user', to='auth.permission', verbose_name='user permissions')),
            ],
            options={
                'verbose_name': 'user',
                'verbose_name_plural': 'users',
                'abstract': False,
            },
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.CreateModel(
            name='Organization',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_on', models.DateTimeField(default=None, editable=False, help_text='The date/time this resource was created')),
                ('modified_on', models.DateTimeField(default=None, editable=False, help_text='The date/time this resource was created')),
                ('name', models.CharField(help_text='The name of this resource', max_length=512, unique=True)),
                ('description', models.TextField(blank=True, default='', help_text='The organization description.')),
                ('created_by', models.ForeignKey(default=None, editable=False, help_text='The user who created this resource', null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='%(app_label)s_%(class)s_created+', to=settings.AUTH_USER_MODEL)),
                ('modified_by', models.ForeignKey(default=None, editable=False, help_text='The user who last modified this resource', null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='%(app_label)s_%(class)s_modified+', to=settings.AUTH_USER_MODEL)),
                ('users', models.ManyToManyField(blank=True, help_text='The list of users in this organization.', related_name='organizations', to=settings.AUTH_USER_MODEL)),
            ],
            options={'default_permissions': ('change', 'delete', 'view')},
        ),
        migrations.CreateModel(
            name='EncryptionModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_on', models.DateTimeField(default=None, editable=False, help_text='The date/time this resource was created')),
                ('modified_on', models.DateTimeField(default=None, editable=False, help_text='The date/time this resource was created')),
                ('name', models.CharField(help_text='The name of this resource', max_length=512, unique=True)),
                ('description', models.TextField(default='', help_text='The organization description.')),
                ('created_by', models.ForeignKey(default=None, editable=False, help_text='The user who created this resource', null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='%(app_label)s_%(class)s_created+', to=settings.AUTH_USER_MODEL)),
                ('modified_by', models.ForeignKey(default=None, editable=False, help_text='The user who last modified this resource', null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='%(app_label)s_%(class)s_modified+', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'abstract': False,
            },
        ),
        migrations.CreateModel(
            name='Team',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_on', models.DateTimeField(default=None, editable=False, help_text='The date/time this resource was created')),
                ('modified_on', models.DateTimeField(default=None, editable=False, help_text='The date/time this resource was created')),
                ('name', models.CharField(help_text='The name of this resource', max_length=512)),
                ('description', models.TextField(blank=True, default='', help_text='The team description.')),
                ('created_by', models.ForeignKey(default=None, editable=False, help_text='The user who created this resource', null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='%(app_label)s_%(class)s_created+', to=settings.AUTH_USER_MODEL)),
                ('modified_by', models.ForeignKey(default=None, editable=False, help_text='The user who last modified this resource', null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='%(app_label)s_%(class)s_modified+', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(help_text='The organization of this team.', on_delete=django.db.models.deletion.CASCADE, related_name='teams', to=settings.ANSIBLE_BASE_ORGANIZATION_MODEL)),
                ('team_parents', models.ManyToManyField(blank=True, related_name='team_children', to=settings.ANSIBLE_BASE_TEAM_MODEL)),
                ('tracked_users', models.ManyToManyField(blank=True, related_name='tracked_teams', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ('organization__name', 'name'),
                'abstract': False,
                'unique_together': {('organization', 'name')},
                'permissions': [('member_team', 'Has all roles assigned to this team')],
            },
        ),
        migrations.CreateModel(
            name='ExampleEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64, unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='InstanceGroup',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=512)),
            ],
            options={
                'default_permissions': ('change', 'delete', 'view'),
            },
        ),
        migrations.RemoveField(
            model_name='encryptionmodel',
            name='description',
        ),
        migrations.AddField(
            model_name='encryptionmodel',
            name='testing1',
            field=models.CharField(default='a', max_length=1, null=True),
        ),
        migrations.AddField(
            model_name='encryptionmodel',
            name='testing2',
            field=models.CharField(default='b', max_length=1, null=True),
        ),
        migrations.AlterField(
            model_name='encryptionmodel',
            name='name',
            field=models.CharField(help_text='The name of this resource', max_length=512),
        ),
        migrations.CreateModel(
            name='Namespace',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64, unique=True)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.ANSIBLE_BASE_ORGANIZATION_MODEL)),
            ],
        ),
        migrations.CreateModel(
            name='Inventory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=512)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.ANSIBLE_BASE_ORGANIZATION_MODEL)),
            ],
            options={
                'permissions': [('update_inventory', 'Do inventory updates')],
            },
        ),
        migrations.CreateModel(
            name='CollectionImport',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=64, unique=True)),
                ('namespace', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='test_app.namespace')),
            ],
        ),
        migrations.CreateModel(
            name='UUIDModel',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='test_app.organization')),
            ],
        ),
        migrations.CreateModel(
            name='Cow',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='test_app.organization')),
            ],
            options={
                'permissions': [('say_cow', 'Make cow say some advice')],
            },
        ),
    ]
