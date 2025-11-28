#!/usr/bin/env python3
"""Serial-based card reader example.

This script communicates with a serial bridge exposing a card reader on
`/dev/ttyACM_back_left` (default). It sends the GET UID APDU and prints
the response. Adapt framing and parsing to match your bridge's protocol.

Usage:
  source at_card_reader_venv/bin/activate
  pip install pyserial
  python serial_card_reader.py --device /dev/ttyACM_back_left
"""

import argparse
import binascii
import logging
import signal
import time
import inspect

import os
import sys

from datetime import datetime
from opcua import Client, ua
from logging.handlers import TimedRotatingFileHandler

try:
	import serial
except Exception:
	raise SystemExit("pyserial is required. Install with: pip install pyserial")

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')

APDU_COMMANDS = {
	"get_uid": {
		"description": "Reads the card's UID.",
		"apdu": [0xFF, 0xCA, 0x00, 0x00, 0x00]
	}
}


def apdu_to_bytes(apdu):
	return bytes(apdu)


def parse_serial_response(line: bytes):
	"""Try to parse the device response.

	Accepts ASCII hex like "04 A2 3F 90 00" or raw bytes. Returns
	(payload_bytes, sw1, sw2) or (None, None, None) if nothing parsed.
	"""
	if not line:
		return None, None, None

	data = None
	# try ASCII hex first
	try:
		text = line.decode('utf-8', errors='ignore').strip()
		# strip non-hex chars except spaces
		filtered = ''.join(ch for ch in text if ch in '0123456789abcdefABCDEF ')
		parts = [p for p in filtered.split() if p]
		if parts:
			data = bytes(int(p, 16) for p in parts)
	except Exception:
		data = None

	# if ascii-hex parsing failed, fall back to raw bytes
	if data is None:
		try:
			data = bytes(line)
		except Exception:
			return None, None, None

	if len(data) >= 2:
		return data[:-2], data[-2], data[-1]
	return data, None, None


def send_apdu_and_read(ser: serial.Serial, apdu: list, add_newline=True):
	b = apdu_to_bytes(apdu)
	ser.write(b)
	if add_newline:
		ser.write(b"\n")
	# read a single line response (device-specific)
	line = ser.readline()
	return parse_serial_response(line)

#-------------------------------------------------------------------------------------------------------------------
# Return the path of the script
# This function is used to get the directory of the script, which is useful for loading configuration
#-------------------------------------------------------------------------------------------------------------------
def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Writing to OPC UA server
#-------------------------------------------------------------------------------------------------------------------
def zapis_do_opc(nodeidrun, value):
    log_and_print(funkce=inspect.currentframe().f_code.co_name, text="Začátek", type_of_log="DEBUG")

    #server_url = "opc.tcp://0.0.0.0:4840"
    global server_url

    client = Client(server_url)

    try:
        client.connect()
    except Exception as ex:
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=nodeidrun + " - " + str(ex), type_of_log="ERROR")
    
    if isinstance(value, bool):
        variant_type = ua.VariantType.Boolean
    elif isinstance(value, int):
        variant_type = ua.VariantType.Int32
    elif isinstance(value, float):
        variant_type = ua.VariantType.Double
    elif isinstance(value, str):
        variant_type = ua.VariantType.String
    else:
        raise ValueError("Unsupported type")

    try:
        node = client.get_node(nodeidrun)

        if value != '':
            #node.set_value(ua.DataValue(ua.Variant(barcode, ua.VariantType.String)))
            node.set_value(ua.DataValue(ua.Variant(value, variant_type)))
            log_and_print(funkce=inspect.currentframe().f_code.co_name, text=str(value), type_of_log="DEBUG")
    except Exception as ex:
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=nodeidrun + " - " + str(ex), type_of_log="ERROR")

    finally:
    # Disconnect from the server
        client.disconnect()     
        #exit()
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Reading from OPC UA server
#-------------------------------------------------------------------------------------------------------------------
def cteni_z_opc(nodeidrun):
    log_and_print(funkce=inspect.currentframe().f_code.co_name, text="Začátek", type_of_log="DEBUG")

    #server_url = "opc.tcp://0.0.0.0:4840"
    global server_url

    ret = None

    client = Client(server_url)

    try:
        client.connect()
    except Exception as ex:
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=nodeidrun + " - " + str(ex), type_of_log="ERROR")

    try:
        node = client.get_node(nodeidrun)

        ret = node.get_value()
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=str(ret), type_of_log="DEBUG")
    except Exception as ex:
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=nodeidrun + " - " + str(ex), type_of_log="ERROR")

    finally:
    # Disconnect from the server
        client.disconnect()     
        #exit()
    return ret
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Log and print taxt and messages at the same time
#-------------------------------------------------------------------------------------------------------------------
def log_and_print(text: str, funkce: str=None, type_of_log: str="INFO"):
    print(text)

    if funkce is not None:
        text = funkce + " : " + text

    if type_of_log == "INFO":
        logger.info(text)
    elif type_of_log == "DEBUG":
        logger.debug(text)
    elif type_of_log == "WARNING":
        logger.warning(text)
    elif type_of_log == "ERROR":
        logger.error(text)
    else:
        logger.info(text)
#------------------------------------------------------------------------------------------------------------------- 

def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('--device', '-d', default='/dev/ttyACM_back_left')
	parser.add_argument('--baud', type=int, default=115200)
	parser.add_argument('--interval', type=float, default=1.0)
	args = parser.parse_args()

	try:
		ser = serial.Serial(args.device, args.baud, timeout=1)
	except Exception as e:
		log_and_print(f'Cannot open serial device {args.device}: {e}', 'main', 'ERROR')
		raise SystemExit(1)

	log_and_print(f'Opened {args.device} @ {args.baud}', 'main', 'INFO')

	stop = False

	def _signal(signum, frame):
		nonlocal stop
		stop = True

	signal.signal(signal.SIGINT, _signal)
	signal.signal(signal.SIGTERM, _signal)

	try:
		while not stop:
			apdu = APDU_COMMANDS['get_uid']['apdu']
			log_and_print(f'Sending APDU: {apdu}', 'main', 'DEBUG')
			payload, sw1, sw2 = send_apdu_and_read(ser, apdu)

			if payload is None or len(payload) == 0:
				log_and_print('No card / no response', 'main', 'DEBUG')
			else:
				log_and_print(str(payload), 'main', 'DEBUG')
				

				hex_payload = binascii.hexlify(payload).decode('ascii').upper()
				if sw1 is not None and sw2 is not None:				
					log_and_print(f'UID: {hex_payload}  SW: {sw1:02X} {sw2:02X}', 'main', 'INFO')
				else:
					log_and_print(f'UID (no SW): {hex_payload}', 'main', 'INFO')

			time.sleep(args.interval)
	finally:
		try:
			ser.close()
		except Exception:
			pass


if __name__ == '__main__':
    #---------------------------------------------------------
    # Setting for logging
    #---------------------------------------------------------
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    actual_dir = get_script_path()
    actual_file_name_py = os.path.basename(__file__)
    actual_file_name = actual_file_name_py.split('.')[0]

    log_dir = actual_dir + "/log"

    if os.path.exists(log_dir) == False:
        os.makedirs(log_dir)

    log_file = actual_file_name + ".log"
    log_path = os.path.join(log_dir, log_file)
    #---------------------------------------------------------

    #-------------------------------------------------
    # Nastavení logování s rotací každý den
    #-------------------------------------------------
    class LogWithDateExtensionHandler(TimedRotatingFileHandler):
        def rotation_filename(self, default_name):
            """
            Rebuild the rotated filename to keep .log extension at the end
            """
            try:
                base, _ = os.path.splitext(default_name)
                root_base, ext = os.path.splitext(base)
                # Use current timestamp for rotation
                date_str = datetime.now().strftime("%Y-%m-%d")
                return f"{root_base}_{date_str}.log"
            except Exception as e:
                return default_name
    # Rotate daily at midnight (or "M" for minutes)
    handler = LogWithDateExtensionHandler(
        log_path,
        when="midnight",
        interval=1,
        backupCount=7
    )
    '''
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    '''
    formatter = logging.Formatter(
        fmt='%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s',
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    #-------------------------------------------------

    log_and_print(text='-----------------------------------------------------')
    log_and_print(text="Začátek")

    main()

