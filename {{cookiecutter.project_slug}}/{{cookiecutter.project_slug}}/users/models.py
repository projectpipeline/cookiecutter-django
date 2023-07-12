from django.contrib.auth.models import AbstractUser, UserManager
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.contenttypes.fields import GenericRelation
from django.core.validators import RegexValidator
from django.db import models
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from guardian.mixins import GuardianUserMixin

from {{ cookiecutter.project_slug }}.base.models import AbstractBaseModel, CustomField


class CustomUserManager(UserManager):
    def get_by_natural_key(self, username):
        return self.get(username=username)


class User(AbstractBaseModel, AbstractUser, GuardianUserMixin):
    __doc__ = _("""
    Table contains cognito-users & django-users.

    PermissionsMixin leverage built-in django model permissions system
    (which allows to limit information for staff users via Groups).

    Note: Django-admin user and app user not split in different tables because of simplicity of development.
    Some libraries assume there is only one user model, and they can't work with both.
    For example to have a history log of changes for entities - to save which user made a change of object attribute,
    perhaps, auth-related libs, and some other.
    With current implementation we don't need to fork, adapt and maintain third party packages.
    They should work out of the box.
    The disadvantage is - cognito-users will have unused fields which always empty. Not critical.
    """)

    class LocaleChoices(models.TextChoices):
        FRENCH = 'fr_CA', _('French')
        ENGLISH = 'en_US', _('English')

    username_validator = UnicodeUsernameValidator()

    ### Common fields ###
    # For cognito-users username will contain `sub` claim from jwt token
    # (unique identifier (UUID) for the authenticated user).
    # For django-users it will contain username which will be used to login into django-admin site

    custom_fields = GenericRelation(
        CustomField,
        related_query_name='user',
        verbose_name=_('Custom Fields'),
        help_text=_('You can set custom fields for complex scenarios.')
    )
    locale = models.CharField(
        verbose_name=_('Locale'),
        max_length=6,
        choices=LocaleChoices.choices,
        default=LocaleChoices.ENGLISH,
        help_text=_('You can set preferred language for user.')
    )
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )

    phone_number = models.CharField(
        validators=[phone_regex],
        max_length=17,
        blank=True,
        null=True
    )

    objects = CustomUserManager()

    USERNAME_FIELD = 'username'
    EMAIL_FIELD = 'email'
    REQUIRED_FIELDS = ['email']  # used only on createsuperuser

    @property
    def is_django_user(self):
        return self.has_usable_password()

    def __str__(self):
        return '{1} {2} <{0}>'.format(self.email, self.first_name, self.last_name)

    def natural_key(self):
        return self.username

    def get_absolute_url(self):
        """Get url for user's detail view.

        Returns:
            str: URL for user detail.

        """
        return reverse("users:detail", kwargs={"username": self.username})
