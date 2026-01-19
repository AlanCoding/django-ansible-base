###
# Noop migration due to removal of FEATURE_DISPATCHERD_ENABLED
###

# FileHash: c86a753d9bf5999274a78c771e5fc23d9dde2fd6c6f630440d28477a658dcf7f

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('dab_feature_flags', '0002_manual_20251222'),
    ]

    operations = [
    ]
