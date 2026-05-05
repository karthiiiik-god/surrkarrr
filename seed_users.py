from app.pages.login import DEFAULT_BOOTSTRAP_USERS, hash_password
from core.storage.database import Database


db = Database()
for username, password, role, full_name in DEFAULT_BOOTSTRAP_USERS:
    db.create_user(
        username,
        hash_password(password),
        role,
        full_name=full_name,
        is_active=True,
    )

print("Seed users created:")
for username, password, role, _ in DEFAULT_BOOTSTRAP_USERS:
    print(f"{role.title()}: {username}/{password}")
