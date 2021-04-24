from secretpy.ciphers import Playfair
import time
from functools import wraps

PROF_DATA = {}


def profile(fn):
    @wraps(fn)
    def with_profiling(*args, **kwargs):
        start_time = time.time()

        ret = fn(*args, **kwargs)

        elapsed_time = time.time() - start_time

        if fn.__name__ not in PROF_DATA:
            PROF_DATA[fn.__name__] = [0, []]
        PROF_DATA[fn.__name__][0] += 1
        PROF_DATA[fn.__name__][1].append(elapsed_time)

        return ret

    return with_profiling


def print_prof_data():
    for fname, data in PROF_DATA.items():
        max_time = max(data[1])
        avg_time = sum(data[1]) / len(data[1])
        print("Function %s called %d times. " % (fname, data[0]),)
        print('Execution time max: %.3f, average: %.3f' % (max_time, avg_time))


def clear_prof_data():
    global PROF_DATA
    PROF_DATA = {}


class RKECryptoModel:

    def __init__(self, message, sk):
        self.msg = message
        self.sk = sk

    @staticmethod
    def get_bit_msg(s):
        return ''.join(format(ord(x), 'b').zfill(8) for x in s)

    @staticmethod
    def get_char_msg(bit_msg):
        n = len(bit_msg)
        i = 0
        tmp = ''
        while i < n:
            tmp += chr(int(bit_msg[i:i+8], 2))
            i += 8
        return tmp

    @profile
    def single_encrypt(self):
        #  Single encryption on last 64 bits out of total 66 bits
        cmd = self.msg[:2]  # Command unlock (00) / lock (01)
        data = self.get_char_msg(self.msg[2:])
        pf = Playfair()
        encrypt_data = pf.encrypt(data, self.sk)
        self.msg = cmd + self.get_bit_msg(encrypt_data)

    @profile
    def double_encrypt(self):
        #  Double encryption on last 32 bits out of total 66 bits
        cmd = self.msg[:2]  # Command unlock (00) / lock (01)
        data1 = self.msg[2:34]
        data2 = self.get_char_msg(self.msg[34:])
        pf = Playfair()
        single_encrypt = pf.encrypt(data2, self.sk)
        double_encrypt = pf.encrypt(single_encrypt, self.sk)
        self.msg = cmd + data1 + self.get_bit_msg(double_encrypt)

    @profile
    def single_decrypt(self):
        #  Single decryption on last 64 bits out of total 66 bits
        cmd = self.msg[:2]  # Command unlock (00) / lock (01)
        encrypt_data = self.get_char_msg(self.msg[2:])
        pf = Playfair()
        data = pf.decrypt(encrypt_data, self.sk)
        self.msg = cmd + self.get_bit_msg(data)

    @profile
    def double_decrypt(self):
        #  Double decryption on last 32 bits out of total 66 bits
        cmd = self.msg[:2]  # Command unlock (00) / lock(01)
        data1 = self.msg[2:34]
        double_encrypt = self.get_char_msg(self.msg[34:])
        pf = Playfair()
        single_encrypt = pf.decrypt(double_encrypt, self.sk)
        data2 = pf.decrypt(single_encrypt, self.sk)
        self.msg = cmd + data1 + self.get_bit_msg(data2)


if __name__ == "__main__":
    st = 'maskmask'
    secret_key = 'mask'
    print('Plain txt:', st)

    msg = RKECryptoModel.get_bit_msg(st)
    msg = '00'+msg

    print('\nSingle Encryption on last 64 bits process:')
    print('At Fob Encrypt:')
    fob = RKECryptoModel(msg, secret_key)
    fob.single_encrypt()
    print('Fob Encrypt Bit:', fob.msg)
    print('Fob Encrypt Char:', fob.get_char_msg(fob.msg[2:]))

    print('At Car Decrypt:')
    car = RKECryptoModel(fob.msg, secret_key)
    car.single_decrypt()
    print('Car Decrypt Bit:', car.msg)
    print('Car Decrypt Char:', car.get_char_msg(car.msg[2:]))

    print('\nDouble Encryption on last 32 bits process:')
    print('At Fob Encrypt:')
    fob_double = RKECryptoModel(msg, secret_key)
    fob_double.double_encrypt()
    print('Fob Encrypt Bit:', fob_double.msg)
    print('Fob Encrypt Char:', fob_double.get_char_msg(fob_double.msg[2:]))

    print('At Car Decrypt:')
    car_double = RKECryptoModel(fob_double.msg, secret_key)
    car_double.double_decrypt()
    print('Car Decrypt Bit:', car_double.msg)
    print('Car Decrypt Char:', car_double.get_char_msg(car_double.msg[2:]))

    print('\nTime Profile:')
    print_prof_data()
