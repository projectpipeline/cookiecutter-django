from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class BaseConfig(AppConfig):
    name = "{{ cookiecutter.project_slug }}.base"
    verbose_name = _("Base")
