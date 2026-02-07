from django.contrib import admin
from apps.users.models import (
    User,
    UserGroup,
    UserRole,
)

# Register your models here.


class BaseAdmin(admin.ModelAdmin):
    def get_list_display(self, request):
        return tuple(field.name for field in self.model._meta.fields)


@admin.register(User)
@admin.register(UserGroup)
@admin.register(UserRole)
class UserAdmin(BaseAdmin):
    pass
