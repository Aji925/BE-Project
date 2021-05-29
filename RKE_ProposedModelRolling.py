from py3rijndael import Rijndael
from twofish import Twofish
import time
import random
import string

seed_no = 231
seed_no1 = 309
seed_no2 = 321
possible_chars = string.ascii_letters + string.digits + string.punctuation

# Applying rijndael(twofish)


class RKE_ProposedModel:
    def __init__(self):
        self.sk1 = ''
        self.sk2 = ''
        self.block_size = 32

    def encrypt(self, msg):
        e_start_ts = time.time()
        start_timestamp = round(time.time(), 5)
        print('Start timestamp at encryption:', start_timestamp, 's')

        random.seed(seed_no1)
        self.sk1 = ''.join(random.choice(possible_chars) for i in range(16))
        algo1 = Twofish(self.sk1.encode('utf-8'))
        encrypt_msg1 = algo1.encrypt(msg.encode('utf-8'))

        random.seed(seed_no2)
        self.sk2 = ''.join(random.choice(possible_chars) for i in range(16))
        algo2 = Rijndael(self.sk2, self.block_size)
        encrypt_msg2 = algo2.encrypt(encrypt_msg1+str(start_timestamp).encode('utf-8'))

        print('Size of encrypt2:', len(encrypt_msg2), 'bytes')
        print('\nSize of encrypt1:', len(encrypt_msg1), 'bytes')

        e_end_ts = time.time()
        print('Time taken for encrypt():', (e_end_ts - e_start_ts) * 10**3, 'ms')

        return encrypt_msg2

    def decrypt(self, msg):
        d_start_ts = time.time()
        end_timestamp = round(time.time(), 5)
        print('End timestamp at decryption:', end_timestamp, 's')

        random.seed(seed_no2)
        self.sk2 = ''.join(random.choice(possible_chars) for i in range(16))
        algo2 = Rijndael(self.sk2, self.block_size)
        decrypt_msg2 = algo2.decrypt(msg)

        random.seed(seed_no1)
        self.sk1 = ''.join(random.choice(possible_chars) for i in range(16))
        algo1 = Twofish(self.sk1.encode('utf-8'))
        decrypt_msg1 = algo1.decrypt(decrypt_msg2[:16])

        print('Size of decrypt1:', len(decrypt_msg1), 'bytes')
        print('\nSize of decrypt2:', len(decrypt_msg2), 'bytes')

        start_timestamp = float((decrypt_msg2[16:]).decode('utf-8'))
        print('Start timestamp extracted at decryption:', start_timestamp)
        diff_timestamp = end_timestamp-start_timestamp

        d_end_ts = time.time()
        print('Time taken for decrypt():', (d_end_ts - d_start_ts) * 10**3, 'ms')

        return decrypt_msg1.decode('utf-8'), diff_timestamp


if __name__ == '__main__':

    random.seed(seed_no)
    plaintext1 = ''.join(random.choice(possible_chars) for i in range(16))

    print('\nPlain text:', plaintext1)
    print('Number of possible values for a letter in both sk:', len(possible_chars))

    fob = RKE_ProposedModel()

    encrypted_msg = fob.encrypt(plaintext1)

    print('\nAt fob, encrypted msg:', encrypted_msg)

    car = RKE_ProposedModel()

    decrypted_msg, diff_timestamp = car.decrypt(encrypted_msg)

    print('\nAt car, decrypted msg:', decrypted_msg)
    print('Difference in Tend - Tstart :', diff_timestamp * 10**3, 'ms')

    random.seed(seed_no)
    plaintext2 = ''.join(random.choice(possible_chars) for i in range(16))

    print('Plain text at car:', plaintext2)
