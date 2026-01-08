import secrets, base64


key_bytes = secrets.token_bytes(32)
key_base64 = base64.urlsafe_b64encode(key_bytes).decode('utf-8')

with open('.env', 'w') as f:
    f.write(f'SECRET_KEY={key_base64}\n')