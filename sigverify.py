from coinsupport import Daemon
from coinsupport.addresscodecs import decode_any_address, encode_base58_address
from coinsupport.coins import GRLC

from config import DAEMON_URL, DAEMON_ADDRESS_VERSION_BYTE


def verify_signature(address, message, signature):
    _, _, pubkeyhash = decode_any_address(address)
    address_for_verification = encode_base58_address(DAEMON_ADDRESS_VERSION_BYTE, pubkeyhash).decode('utf-8')
    address_for_account_id = encode_base58_address(GRLC['address_version'], pubkeyhash).decode('utf-8')

    if not Daemon(DAEMON_URL).verifymessage(address_for_verification, signature, message):
        return None

    return address_for_account_id
