from py3rijndael import Rijndael
from twofish import Twofish
import time
import random
import string

sk = 'ajinkya123456789'
seed_no = 234

'''
# Rijndael testing
key = 'ajinkya123456789'

print('Using Rijndael key = ', key, ' block size =', 16)

obj = Rijndael(key, block_size=16)

plaintext = '321manandeep1234'

print('Plain text:', plaintext)

encrypt_text = obj.encrypt(plaintext)

print('Encrypted Text:', encrypt_text)

decrypt_text = obj.decrypt(encrypt_text)

print('Decrypted text:', decrypt_text)
'''

'''
# Twofish testing
key = 'ajinkya123456789'

obj = Twofish(key.encode('utf-8'))

plaintext = '321manandeep1234'

print('Plain text: ', plaintext)

encrypt_text = obj.encrypt(plaintext.encode('utf-8'))

print('Encrypted text: ', encrypt_text)

decrypt_text = obj.decrypt(encrypt_text).decode('utf-8')

print('Decrypted text: ', decrypt_text)

'''
# Applying rijndael(twofish)


class RKE_ProposedModel:
    def __init__(self, key, block_size):
        self.sk = key
        self.block_size = block_size

    def encrypt(self, msg):
        algo1 = Twofish((self.sk).encode('utf-8'))
        encrypt_msg1 = algo1.encrypt(msg.encode('utf-8'))
        print('\nSize of encrypt1:', len(encrypt_msg1))

        start_timestamp = round(time.time(), 5)
        print('Start timestamp at encryption:', start_timestamp)

        algo2 = Rijndael(self.sk, self.block_size)
        encrypt_msg2 = algo2.encrypt(encrypt_msg1+str(start_timestamp).encode('utf-8'))
        print('Size of encrypt2:', len(encrypt_msg2))

        return encrypt_msg2

    def decrypt(self, msg):
        algo2 = Rijndael(self.sk, self.block_size)
        decrypt_msg2 = algo2.decrypt(msg)
        print('\nSize of decrypt2:', len(decrypt_msg2))

        algo1 = Twofish((self.sk).encode('utf-8'))
        decrypt_msg1 = algo1.decrypt(decrypt_msg2[:16])
        print('Size of decrypt1:', len(decrypt_msg1))

        start_timestamp = float((decrypt_msg2[16:]).decode('utf-8'))
        print('Start timestamp extracted at decryption:', start_timestamp)
        end_timestamp = round(time.time(), 5)
        print('End timestamp at decryption:', end_timestamp)
        diff_timestamp = end_timestamp-start_timestamp

        return decrypt_msg1.decode('utf-8'), diff_timestamp


if __name__ == '__main__':

    random.seed(seed_no)
    plaintext1 = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(16))

    print('Plain text:', plaintext1)

    fob = RKE_ProposedModel(sk, block_size=32)

    encrypted_msg = fob.encrypt(plaintext1)

    print('\nAt fob, encrypted msg:', encrypted_msg)

    car = RKE_ProposedModel(sk, block_size=32)

    decrypted_msg, diff_timestamp = car.decrypt(encrypted_msg)

    print('\nAt car, decrypted msg:', decrypted_msg)
    print('Difference in Tend - Tstart :', diff_timestamp)

    random.seed(seed_no)
    plaintext2 = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(16))

    print('Plain text:', plaintext2)
