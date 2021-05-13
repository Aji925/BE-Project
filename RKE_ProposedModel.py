from py3rijndael import Rijndael
from twofish import Twofish
import time

plaintext = '321manandeep1234'
sk = 'ajinkya123456789'

# Applying rijndael(twofish)


class RKE_ProposedModel:
    def __init__(self, key, block_size):
        self.sk = key
        self.block_size = block_size

    def encrypt(self, msg):
        e_start_ts = time.time()
        start_timestamp = round(time.time(), 5)
        print('Start timestamp at encryption:', start_timestamp, 's')

        algo1 = Twofish(self.sk.encode('utf-8'))
        encrypt_msg1 = algo1.encrypt(msg.encode('utf-8'))

        algo2 = Rijndael(self.sk, self.block_size)
        encrypt_msg2 = algo2.encrypt(encrypt_msg1+str(start_timestamp).encode('utf-8'))

        print('\nSize of encrypt1:', len(encrypt_msg1), 'bytes')
        print('Size of encrypt2:', len(encrypt_msg2), 'bytes')

        e_end_ts = time.time()
        print('Time taken for encrypt():', (e_end_ts - e_start_ts) * 10**3, 'ms')

        return encrypt_msg2

    def decrypt(self, msg):
        d_start_ts = time.time()
        end_timestamp = round(time.time(), 5)
        print('End timestamp at decryption:', end_timestamp, 's')

        algo2 = Rijndael(self.sk, self.block_size)
        decrypt_msg2 = algo2.decrypt(msg)

        algo1 = Twofish(self.sk.encode('utf-8'))
        decrypt_msg1 = algo1.decrypt(decrypt_msg2[:16])

        print('\nSize of decrypt2:', len(decrypt_msg2), 'bytes')
        print('Size of decrypt1:', len(decrypt_msg1), 'bytes')

        start_timestamp = float((decrypt_msg2[16:]).decode('utf-8'))
        print('Start timestamp extracted at decryption:', start_timestamp, 's')
        diff_timestamp = end_timestamp-start_timestamp

        d_end_ts = time.time()
        print('Time taken for decrypt():', (d_end_ts - d_start_ts) * 10**3, 'ms')

        return decrypt_msg1.decode('utf-8'), diff_timestamp


if __name__ == '__main__':

    print('Plain text:', plaintext)

    fob = RKE_ProposedModel(sk, block_size=32)

    encrypted_msg = fob.encrypt(plaintext)

    print('\nAt fob, encrypted msg:', encrypted_msg)

    car = RKE_ProposedModel(sk, block_size=32)

    decrypted_msg, diff_timestamp = car.decrypt(encrypted_msg)

    print('\nAt car, decrypted msg:', decrypted_msg)
    print('Difference in Tend - Tstart :', diff_timestamp * 10**3, 'ms')
