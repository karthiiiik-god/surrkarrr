from core.storage.database import Database
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

db = Database()
admin_hash = pwd_context.hash("admin")
analyst_hash = pwd_context.hash("view123")

db.create_user("admin", admin_hash, "admin")
db.create_user("analyst", analyst_hash, "analyst")

print("Seed users created:")
print("Admin: admin/admin")
print("Analyst: analyst/view123")
