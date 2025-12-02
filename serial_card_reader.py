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
import json
import threading

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

server_url = "opc.tcp://0.0.0.0:4840"

continue_reading = True

APDU_COMMANDS = {
    "get_uid": {
        "description": "Reads the card's UID.",
        "apdu": [0xFF, 0xCA, 0x00, 0x00, 0x00]
    },
    "beep": {
        "description": "Makes the reader beep.",
        "apdu": [0xFF, 0x00, 0x40, 0x00, 0x01, 0x01]  # Common beep command
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

    # Only extract SW if we have 3+ bytes AND last two look like status words (90 00, 61 xx, etc.)
    if len(data) >= 3 and (data[-2] in [0x90, 0x61, 0x62, 0x63, 0x64, 0x65]):
        return data[:-2], data[-2], data[-1]

    # Otherwise, treat entire response as payload with no status words
    return data, None, None


def send_apdu_and_read(ser: serial.Serial, apdu: list, add_newline=True):
    b = apdu_to_bytes(apdu)
    
    try:
        ser.write(b)
        if add_newline:
            ser.write(b"\n")
                
        # wait for device to process and respond
        # read a single line response (device-specific)
        line = ser.readline()
        
        return_value = parse_serial_response(line)

        if return_value == (None, None, None):
            log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Sent APDU: {binascii.hexlify(b).decode('ascii').upper()}, No valid response received", type_of_log="DEBUG")
        else:
            log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Sent APDU: {binascii.hexlify(b).decode('ascii').upper()}, Received: {binascii.hexlify(line).decode('ascii').upper()}", type_of_log="DEBUG")
    except Exception as e:
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Error sending APDU {binascii.hexlify(b).decode('ascii').upper()}: {e}", type_of_log="ERROR")
        zapis_do_opc(code_health_check, False)
        return None, None, None

    return return_value

#-------------------------------------------------------------------------------------------------------------------
# Return the path of the script
# This function is used to get the directory of the script, which is useful for loading configuration
#-------------------------------------------------------------------------------------------------------------------
def get_script_path():
    return os.path.dirname(os.path.realpath(sys.argv[0]))
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Function to clean up old log files
#-------------------------------------------------------------------------------------------------------------------
def cleanup_old_logs(log_dir, days_to_keep=30):
    """
    Delete log files older than specified number of days
    
    Args:
        log_dir: Directory containing log files
        days_to_keep: Number of days to keep log files (default: 30)
    """
    try:
        from datetime import timedelta
        
        if not os.path.exists(log_dir):
            return
        
        # Calculate the cutoff date
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        cutoff_timestamp = cutoff_date.timestamp()
        
        deleted_count = 0
        
        # Iterate through all files in log directory
        for filename in os.listdir(log_dir):
            if filename.endswith('.log'):
                file_path = os.path.join(log_dir, filename)
                
                # Get file modification time
                file_mtime = os.path.getmtime(file_path)
                
                # Delete if older than cutoff date
                if file_mtime < cutoff_timestamp:
                    try:
                        os.remove(file_path)
                        deleted_count += 1
                        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Deleted old log file: {filename}", type_of_log="DEBUG")
                    except Exception as e:
                        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Failed to delete {filename}: {e}", type_of_log="WARNING")
        
        if deleted_count > 0:
            log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Cleaned up {deleted_count} old log file(s)", type_of_log="INFO")
            
    except Exception as e:
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Error during log cleanup: {e}", type_of_log="ERROR")
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Function to load configuration from JSON file
#-------------------------------------------------------------------------------------------------------------------
def load_config(config_file=None):
    """Load configuration from JSON file with default values"""
    if config_file is None:
        script_dir = get_script_path()
        config_file = os.path.join(script_dir, 'serial_card_reader.json')
    
    try:
        with open(config_file) as f:
            config = json.load(f)
            
            # Load configuration with default values
            pPort = config.get('port', '/dev/ttyACM_back_left')
            pBaudrate = config.get('baudrate', 115200)
            pInterval = config.get('interval', 1.0)
            code = config.get('code', 'ns=1;i=100011')
            code_potvrzeni = config.get('code_potvrzeni', 'ns=1;i=100012')
            code_health_check = config.get('code_health_check', 'ns=1;i=100013')
            code_health_check_message = config.get('code_health_check_message', 'ns=1;i=100014')
            log_retention_days = config.get('log_retention_days', 30)  # Keep logs for 30 days
            
            log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Configuration loaded from: {config_file}", type_of_log="DEBUG")
            return {
                'port': pPort,
                'baudrate': pBaudrate,
                'interval': pInterval,
                'code': code,
                'code_potvrzeni': code_potvrzeni,
                'code_health_check': code_health_check,
                'code_health_check_message': code_health_check_message,
                'log_retention_days': log_retention_days
            }
    except FileNotFoundError:
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Config file not found: {config_file}", type_of_log="WARNING")
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text="Using default configuration values", type_of_log="INFO")
        return {
            'port': '/dev/ttyACM_back_left',
            'baudrate': 115200,
            'interval': 1.0,
            'code': 'ns=1;i=100011',
            'code_potvrzeni': 'ns=1;i=100012',
            'code_health_check': 'ns=1;i=100013',
            'code_health_check_message': 'ns=1;i=100014',
            'log_retention_days': 30
        }
    except json.JSONDecodeError as e:
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Error decoding JSON config: {e}", type_of_log="ERROR")
        sys.exit(1)
    except Exception as e:
        log_and_print(funkce=inspect.currentframe().f_code.co_name, text=f"Error reading configuration: {e}", type_of_log="ERROR")
        sys.exit(1)
#-------------------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------------------------
# Writing to OPC UA server
#-------------------------------------------------------------------------------------------------------------------
def zapis_do_opc(nodeidrun, value):
    log_and_print(funkce=inspect.currentframe().f_code.co_name, text="Začátek", type_of_log="DEBUG")

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

#------------------------------------------------------------------------------------------------------------------- 
# Get the current date and time in the format YYYY_MM_DD__HH_MM_SS
#------------------------------------------------------------------------------------------------------------------- 
def actual_date_time():
    """
    Returns the current date and time in the format YYYY_MM_DD__HH_MM_SS
    """
    curr_time = datetime.now()
    return curr_time.strftime('%Y_%m_%d__%H_%M_%S_%f')
#------------------------------------------------------------------------------------------------------------------- 

def read(pPort, pBaudrate, pInterval, stop_event):
    parser = argparse.ArgumentParser()
    parser.add_argument('--device', '-d', default=pPort)
    parser.add_argument('--baud', type=int, default=pBaudrate)
    parser.add_argument('--interval', type=float, default=pInterval)
    args = parser.parse_args()

    try:
        ser = serial.Serial(args.device, args.baud, timeout=1)
    except Exception as e:
        log_and_print(f'Cannot open serial device {args.device}: {e}', 'main', 'ERROR')
        zapis_do_opc("ns=2;s=CardReader.Error", f'Cannot open serial device {args.device}: {e}')
        raise SystemExit(1)


    log_and_print(f'Opened {args.device} @ {args.baud}', 'main', 'INFO')

    try:
        while not stop_event.is_set():

            apdu = APDU_COMMANDS['get_uid']['apdu']
            log_and_print(f'Sending APDU: {apdu}', 'main', 'DEBUG')
            payload, sw1, sw2 = send_apdu_and_read(ser, apdu)

            if payload is None or len(payload) == 0:
                log_and_print('No card / no response', 'main', 'DEBUG')
            else:
                log_and_print(str(payload), 'main', 'DEBUG')
                zapis_do_opc(code, str(payload))

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

#-------------------------------------------------------------------------------------------------------------------
# Main function to start the scanner thread
#-------------------------------------------------------------------------------------------------------------------
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

    # Load configuration from JSON file
    config = load_config()
    pPort = config['port']
    pBaudrate = config['baudrate']
    pInterval = config['interval']
    code = config['code']
    code_potvrzeni = config['code_potvrzeni']
    code_health_check = config['code_health_check']
    code_health_check_message = config['code_health_check_message']
    log_retention_days = config['log_retention_days']
    
    # Clean up old log files
    cleanup_old_logs(log_dir, log_retention_days)
    
    zapis_do_opc(code_health_check, True)
    zapis_do_opc(code_health_check_message, f'OK')

    # Create a threading event to signal thread shutdown
    stop_event = threading.Event()

    # Signal handlers - must be in main thread
    def _signal_handler(signum, frame):
        log_and_print("Received signal, stopping...", 'main', 'INFO')
        stop_event.set()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    card_reader = threading.Thread(target=read, args=(pPort, pBaudrate, pInterval, stop_event))
    card_reader.daemon = False
    card_reader.start()

    try:
        # Keep the main thread alive
        while card_reader.is_alive():
            card_reader.join(timeout=1)
    except KeyboardInterrupt:
        pass

    card_reader.join()

    log_and_print("Konec", actual_date_time())
    log_and_print('-----------------------------------------------------')
#-------------------------------------------------------------------------------------------------------------------

