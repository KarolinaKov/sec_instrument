from rest_framework.permissions import BasePermission

SENIOR_GROUP = 'senior'
JUNIOR_GROUP = 'junior'


class IsSenior(BasePermission):
    """
    Allows access only to users in the 'senior' group (or superusers).
    Seniors can add, delete, and download tests.
    """
    message = 'Only senior users can perform this action.'

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user and user.is_authenticated and
            (user.is_superuser or user.groups.filter(name=SENIOR_GROUP).exists())
        )


class IsSeniorOrJunior(BasePermission):
    """
    Allows access to users in either the 'senior' or 'junior' group (or
    superusers). Juniors can only view/download tests, not add or delete
    them - enforce that split at the view/action level, not here.
    """
    message = 'You must belong to the senior or junior group.'

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user and user.is_authenticated and
            (user.is_superuser or user.groups.filter(name__in=[SENIOR_GROUP, JUNIOR_GROUP]).exists())
        )
