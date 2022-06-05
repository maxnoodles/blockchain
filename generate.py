import base64

import ecdsa

from utils import CURVE


def generate_ECDSA_keys():
    sk = ecdsa.SigningKey.generate(curve=CURVE)  # this is your sign (private key)
    vk = sk.get_verifying_key()  # this is your verification key (public key)
    public_key = base64.b64encode(vk.to_string()).decode()
    private_key = sk.to_string().hex()
    return public_key, private_key


if __name__ == '__main__':
    public_key, private_key = generate_ECDSA_keys()
    print("address:{0}".format(public_key))
    print("private_key:{0}".format(private_key))
