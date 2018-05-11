from coinkit import BitcoinKeypair
from pybitcointools import deterministic
import logging


class Wallet:
    def __init__(self, passphrase, is_private_key = 0):
        self.passphrase = passphrase
        self.address = None
        self.public_key = None
        self.private_key = None
        try:
            if is_private_key == 1:
                keypair = BitcoinKeypair.from_private_key(self.passphrase.encode('ascii'))
            elif is_private_key == 2:
                keypair = BitcoinKeypair.from_private_key(deterministic.electrum_stretch(self.passphrase))
            else:
                keypair = BitcoinKeypair.from_passphrase(self.passphrase)
            self.address = keypair.address()
            self.public_key = keypair.public_key()
            self.private_key = keypair.private_key()
        except Exception as e:
            logging.warning(u"Failed to generate keypair for passphrase '{}'. Error: {}".format(passphrase, e.args))
            raise