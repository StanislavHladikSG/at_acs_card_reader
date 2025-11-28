import logging
import time

from smartcard.System import readers
from smartcard.util import toHexString

from smartcard.Exceptions import NoCardException

APDU_COMMANDS = {
    "get_uid": {
        "description": "Reads the card's UID.",
        "apdu": [0xFF, 0xCA, 0x00, 0x00, 0x00]
    },   
    #"select_file": {
    #    "description": "Selects a file or application on the card.",
    #    # Example: [0x00, 0xA4, 0x04, 0x00, <Lc>, <Data>, <Le>]
    #    "apdu": lambda lc, data, le: [0x00, 0xA4, 0x04, 0x00, lc] + data + [le]
    #},
    "read_binary": {
        "description": "Reads binary data from the card.",
        # Example: [0x00, 0xB0, <P1>, <P2>, <Le>]
        "apdu": lambda p1, p2, le: [0x00, 0xB0, p1, p2, le]
    },
    "update_binary": {
        "description": "Writes binary data to the card.",
        # Example: [0x00, 0xD6, <P1>, <P2>, <Lc>, <Data>]
        "apdu": lambda p1, p2, lc, data: [0x00, 0xD6, p1, p2, lc] + data
    },
    "get_response": {
        "description": "Gets additional response data.",
        # Example: [0x00, 0xC0, 0x00, 0x00, <Le>]
        "apdu": lambda le: [0x00, 0xC0, 0x00, 0x00, le]
    }
}

# List available readers
r = readers()
if not r:
    print("No smart card readers found.")
    exit()

reader = r[0]
print(f"Using reader: {reader}")

connection = reader.createConnection()

while True:
    try:
        connection.connect()
        print("Card detected!")

        '''
        response, sw1, sw2 = connection.transmit(APDU_COMMANDS["get_uid"]["apdu"])
        print("Response:", toHexString(response))
        print("Status words: %02X %02X" % (sw1, sw2))
        '''
        
        for command, details in APDU_COMMANDS.items():
            print("----------------------------------------------------------------")
            print(f"Command: {command}, Description: {details['description']}")

            response, sw1, sw2 = connection.transmit(APDU_COMMANDS[command]["apdu"])
            print("Response:", toHexString(response))
            print("Status words: %02X %02X" % (sw1, sw2))
            print("----------------------------------------------------------------")

        # Wait for card removal before next check
        while True:
            try:
                connection.connect()
                time.sleep(0.5)
            except NoCardException:
                print("Card removed.")
                break
    except NoCardException:
        print("No card present. Waiting...")
        time.sleep(1)
