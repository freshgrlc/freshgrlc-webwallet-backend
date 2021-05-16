from coinsupport import Daemon
from coinsupport.addresscodecs import decode_any_address, encode_base58_address
from coinsupport.coins import GRLC

from config import DAEMON_URL, DAEMON_ADDRESS_VERSION_BYTE

COIN = GRLC


def verify_signature(address, message, signature):
    type, version, pubkeyhash = decode_any_address(address)
    address_for_verification = encode_base58_address(DAEMON_ADDRESS_VERSION_BYTE, pubkeyhash).decode('utf-8')
    if type != 'base58':
        version = COIN['segwit_info']['address_version'] if 'address_version' in COIN['segwit_info'] else COIN['address_version']
    address_for_account_id = encode_base58_address(version, pubkeyhash).decode('utf-8')

    if not Daemon(DAEMON_URL).verifymessage(address_for_verification, signature, message):
        return None

    return address_for_account_id
