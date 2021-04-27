from secretpy.ciphers import Playfair
import time
from functools import wraps
import signal
import logging
import RPi.GPIO as GPIO
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

	rfdevice = None

	logging.basicConfig(level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S',
		            format='%(asctime)-15s - Receiving %(message)s')

	args = 27
	decrypt_msg = ""
	ll_wanted_bits = ["12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22"]
	#ll_imp_bits = ["00", "01", "10", "11"]
	ll_bits = list()
	ll_bits_rev = list()
	new_bits = ""

	rfdevice = RFDevice(args)
	rfdevice.enable_rx()
	timestamp = None
	logging.info('')

	i = 0
	while (True):
		if rfdevice.rx_code_timestamp != timestamp and rfdevice.rx_code != None:
			timestamp = rfdevice.rx_code_timestamp
			#print(rfdevice.rx_code)
			ll_bits.append(rfdevice.rx_code)
			#print(ll_bits)
			logging.info(str(rfdevice.rx_code))
		   
		if "22" in str(rfdevice.rx_code):
			break

		time.sleep(1)

	ll_bits = sorted(set(ll_bits), key=ll_bits.index)

	for i in ll_bits:
		i = str(i)    
		if len(i) >= 2 and len(i) <= 8:
			if i[0:2] in ll_wanted_bits:
				last_four_bits = i[2:len(i)]
				if "2" in  last_four_bits or "3" in  last_four_bits or "4" in  last_four_bits or "5" in  last_four_bits or "6" in  last_four_bits or "7" in  last_four_bits or "8" in  last_four_bits or "9" in  last_four_bits:
					print("I in pass block", i)
				else:
					new_bits = i.replace(i[0:2], '')
					ll_bits_rev.append(new_bits)


	final_bits = ''.join(ll_bits_rev)
	print(final_bits)

	#final_bits = "000110110101100001011100110110101101110011011010110110001001101101"
	print('At Car Decrypt:')
	car_double = RKECryptoModel(final_bits, secret_key)
	car_double.double_decrypt()
	print('Car Decrypt Bit:', car_double.msg)
	print('Car Decrypt Char:', car_double.get_char_msg(car_double.msg[2:]))


