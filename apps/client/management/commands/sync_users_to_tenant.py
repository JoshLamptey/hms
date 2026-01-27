# =====Use this for totally isolated tenants if you want to keep user data separate per tenant====#


# from django.core.management.base import BaseCommand
# from apps.users.models import User


# class Command(BaseCommand):
#     help = "Sync users to tenant schema"

#     def handle(self, *args, **options):
#         users = User.objects.filter(tenant__isnull=False)
#         total = users.count()

#         self.stdout.write(f"Starting to sync {total} users to their respective tenant schemas.")

#         for i, user in enumerate(users, 1):
#             try:
#                 user.save()
#                 if i % 100 ==0:
#                     print(f"processed {i}/{total} users")
#                     self.stdout.write(f"Processed {i}/{total} users.")
#             except Exception as e:
#                 self.stderr.write(f"Error syncing user {user.id}: {e}")


#         self.stdout.write(f"{total}users sync to tenant schemas completed.")
