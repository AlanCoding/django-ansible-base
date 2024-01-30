from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from test_app.models import CollectionImport, EncryptionModel, ExampleEvent, Namespace, Organization, Team, User, Inventory, InstanceGroup

admin.site.register(EncryptionModel)
admin.site.register(Organization)
admin.site.register(Team)
admin.site.register(User, UserAdmin)
admin.site.register(Namespace)
admin.site.register(CollectionImport)
admin.site.register(Inventory)
admin.site.register(InstanceGroup)
admin.site.register(ExampleEvent)
