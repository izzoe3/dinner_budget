from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()
print(bcrypt.generate_password_hash('Aobcd8663').decode('utf-8'))
print(bcrypt.generate_password_hash('Aobcd8663').decode('utf-8'))