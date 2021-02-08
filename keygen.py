import os
import gnupg

gpg = gnupg.GPG(gnupghome='./utils/.gnupg')
gpg.encoding = 'utf-8'

input_data = gpg.gen_key_input(
    name_email = 'example@example.com',
    passphrase = 'something',
    key_type = 'RSA',
    key_length = 2048
)

key = gpg.gen_key(input_data)

print(key)
