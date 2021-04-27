
from secretpy.ciphers import Playfair
import time
from functools import wraps
import logging
import subprocess as sp
import time
from rpi_rf import RFDevice

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


	logging.basicConfig(level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S',
			    format='%(asctime)-15s - Sending: %(message)s')


	TX_pin = 17

	code = fob.msg
	identifier = 12
	ll_bits = list()
	#code = "1234"

	rfdevice = RFDevice(TX_pin)
	rfdevice.enable_tx()

	for i in range(0,66,6):
	    code_break = code[i:i+6]
	    code_break = str(identifier) + code_break
	    ll_bits.append(int(code_break))
	    identifier += 1

	for i in ll_bits:
	    rfdevice.tx_code(int(i))
	    logging.info(str(i))
	    time.sleep(2)

	rfdevice.cleanup()


	