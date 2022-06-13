import base64
from datetime import datetime

import ecdsa

CURVE = ecdsa.SECP256k1


def time_format(_time: datetime, _format="%Y-%m-%d %H:%M:%S.%f"):
    return _time.strftime(_format)


def sign_data(private_key: str, data: dict, _time: str):
    sig_str = build_to_sig_str(data, _time)
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=CURVE)
    signature = base64.b64encode(sk.sign(sig_str.encode())).hex()
    return signature


def validate_signature(signature, data, _time):
    to_sig_str = build_to_sig_str(data, _time)
    return valide_ECDSA_sign(data["from"], signature, to_sig_str)


def build_to_sig_str(data, _time):
    values = [str(data[k]) for k in sorted(data.keys())]
    sig_str = f"{''.join(values)}{_time}"
    return sig_str


def valide_ECDSA_sign(public_key: str, sign: str, to_sig_str):
    public_key = base64.b64decode(public_key)
    signature = base64.b64decode(bytes.fromhex(sign))
    vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    try:
        return vk.verify(signature, to_sig_str.encode())
    except:
        return False


def generate_ECDSA_keys():
    sk = ecdsa.SigningKey.generate(curve=CURVE)  # this is your sign (private key)
    vk = sk.get_verifying_key()  # this is your verification key (public key)
    public_key = base64.b64encode(vk.to_string()).decode()
    private_key = sk.to_string().hex()
    return public_key, private_key


if __name__ == '__main__':
    sk = "8c3e50b78fb48eb7761b95561f4ecdd66aa04e180286df93d1507dd63a46a45d"
    from_address = "ewEf9xFJV1Bt6/7+gjkfebvlmcuY6wuhXsHqKPGyuCgqguxFjzEV+ayQiwTkPy8gtVuEJRg+nfmRN853RLTFXg=="
    to_address = "TnK1vobvj8MRmyN2Y6ZgARj5HCtpMKg+YvjN2c8X39mplufWciP5TxNhOUaCLZT7NNGXnArjg6ZTrgwdprj7qg=="
    data = {
        "from": from_address,
        "to": to_address,
        "memo": "123"
    }
    _time = time_format(datetime.now())
    sign = sign_data(sk, data, _time)
    print(sign)
    ret = validate_signature(sign, data, _time)
    assert ret == True
