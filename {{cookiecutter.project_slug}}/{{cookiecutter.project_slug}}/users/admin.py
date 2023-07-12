from django.contrib import admin
from django.contrib.auth import admin as auth_admin
from django.db.models import JSONField
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.admin import GenericTabularInline
from django.utils.translation import gettext_lazy as _
from django_json_widget.widgets import JSONEditorWidget
from djangoql.admin import DjangoQLSearchMixin

from {{ cookiecutter.project_slug }}.base.models import CustomField

User = get_user_model()


class CustomFieldInline(GenericTabularInline):
    model = CustomField
    extra = 1
    ct_field_name = 'content_type'
    id_field_name = 'object_id'


@admin.register(User)
class UserAdmin(DjangoQLSearchMixin, auth_admin.UserAdmin):
    inlines = (CustomFieldInline,)
    fieldsets = (
        (None, {
            'fields': (
                'username', 'email', 'locale',
                'first_name', 'last_name', 'password',
                'company_name', 'phone_number', 'roles', 'category',
                'associator', 'configuration'
            )
        }
         ),
        (
            _('Permissions'),
            {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions',)}
        ),
        (_('Important dates'), {'fields': ('created_at', 'updated_at',)}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('username', 'email', 'password1', 'password2',),
        }),
    )

    readonly_fields = (
        'created_at',
        'updated_at',
    )

    list_display = (
        'uuid',
        'username',
        'phone_number',
        'is_superuser',
        'first_name',
        'last_name',
        'is_active',
        'email',
        'locale',
        'is_staff',
        'created_at',
        'updated_at',
    )
    list_filter = (
        'last_login',
        'is_superuser',
        'is_active',
        'is_staff',
        'created_at',
        'updated_at',
    )
    date_hierarchy = 'updated_at'
    formfield_overrides = {
        JSONField: {'widget': JSONEditorWidget(mode='form')},
    }
