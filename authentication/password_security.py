
from werkzeug.security import generate_password_hash, check_password_hash

# Create a password
password = "MySecurePassword123"

# Generate password hash
hashed_password = generate_password_hash(password)

print("Original password:", password)
print("Hashed password:", hashed_password)

# Verify password
if check_password_hash(hashed_password, password):
    print("Password is correct")
else:
    print("Incorrect password")
