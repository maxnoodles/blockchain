import base64
import hashlib
import json
from datetime import datetime

import ecdsa

CURVE = ecdsa.SECP256k1


def validate_script(redeem_script, out_data, un_script=None):
    match out_data.get("script_type"):
        case "P2SH":
            """
               两个脚本经由两步实现组合。 首先，将 unlock_script 与 lock_script 比对以确认其与哈希是否匹配
               <2 PK1 PK2 PK3 3 CHECKMULTISIG> HASH <redeem scriptHash> EQUAL
               假如兑换脚本哈希匹配，解锁脚本自行执行以解锁兑换脚本
               <Sig1> <Sig2> 2 PK1 PK2 PK3 3 CHECKMULTISIG
            """
            lock_script = out_data.pop('script_hash').lstrip("OP_HASH")
            redeem_hash = hash_256(redeem_script)
            return eval_script(f"{redeem_hash} {lock_script} {un_script}", out_data)
        case "P2PKH":
            lock_script = out_data.pop('script_pubkey')
            return eval_script(f"{redeem_script} {lock_script}", out_data)
        case "P2PK":
            return True
    return False


def eval_script(script, out_data):
    stack = []
    tax_list = script.strip().split()
    for tax in tax_list:
        match tax:
            case "OP_EQUALVERIFY":
                # 移除栈顶2个元素，并比较是否相等
                if stack.pop() == stack.pop():
                    continue
                else:
                    return False
            case "OP_DUP":
                stack.append(stack[-1])
            case "OP_HASH":
                stack[-1] = hash_256(stack[-1])
            case "OP_CHECKSIG":
                # 检测签名
                # <sig> <pubk> OP_CHECKSIG
                pubk = stack.pop()
                sig = stack.pop()
                if not validate_signature(pubk, sig, out_data):
                    return False
            case "OP_CHECKMULTISIG":
                # 检测多重签名
                # <Signature B> <Signature C> 2 <Public Key A> <Public Key B> <Public Key C> 3 CHECKMULTISIG
                pk_nums = stack.pop()
                pk_lists = [stack.pop() for _ in range(int(pk_nums))]
                sig_nums = stack.pop()
                sig_lists = [stack.pop() for _ in range(int(sig_nums))]
                if not validate_multi_sign(pk_lists, sig_lists, out_data):
                    return False
            case str() as s:
                stack.append(s)

    return True if not stack else False


def validate_multi_sign(pk_lists, sig_lists, out_data):
    success_count = 0
    for sig in sig_lists:
        for pk in pk_lists:
            if validate_signature(pk, sig, out_data):
                success_count += 1
    if success_count == len(sig_lists):
        return True
    return False


def time_format(_time: datetime, _format="%Y-%m-%d %H:%M:%S.%f"):
    return _time.strftime(_format)


def hash_256(s):
    return hashlib.sha256(s.encode()).hexdigest()


def sign_data(private_key: str, data: dict):
    sig_byte = build_to_sig_byte(data)
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key), curve=CURVE)
    signature = base64.b64encode(sk.sign(sig_byte)).hex()
    return signature


def validate_signature(public_key, signature, data):
    to_sig_byte = build_to_sig_byte(data)
    return validate_ecdsa_sign(public_key, signature, to_sig_byte)


def build_to_sig_byte(data):
    return json.dumps(data, sort_keys=True).encode()


def validate_ecdsa_sign(public_key: str, sign: str, to_sig_byte: bytes):
    public_key = base64.b64decode(public_key)
    signature = base64.b64decode(bytes.fromhex(sign))
    vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    try:
        return vk.verify(signature, to_sig_byte)
    except:
        return False


def generate_ecdsa_keys():
    sk = ecdsa.SigningKey.generate(curve=CURVE)  # this is your sign (private key)
    vk = sk.get_verifying_key()  # this is your verification key (public key)
    public_key = base64.b64encode(vk.to_string()).decode()
    private_key = sk.to_string().hex()
    return public_key, private_key


if __name__ == '__main__':
    one = ('c+CbBAqicDyNKnCjJRM9Pm7UASbFCe7uJ4X/3tgAiQzpNmbpHKdW42j084XPy3DRviQ5pf5l7RgAkhtTp72o9A==',
           '5b213f48bc40af3c124973d6d86fe3999db79577c981d6570e193c4f4cc20b2b')

    two = ('b/yxkZEKj1odMvXHFV5IXV0KWQcha4ZBMHRciiS7QsTKgw1KCOrRz6VaWvwB+2fBLiMjBAMYuYUHoggPWq8dtA==',
           '35d10cb7f0ba220e57a62970ab4c6eee921b7b5bb97f6177dde9b6b775719f19')

    sk = "8c3e50b78fb48eb7761b95561f4ecdd66aa04e180286df93d1507dd63a46a45d"
    from_address = "ewEf9xFJV1Bt6/7+gjkfebvlmcuY6wuhXsHqKPGyuCgqguxFjzEV+ayQiwTkPy8gtVuEJRg+nfmRN853RLTFXg=="
    to_address = "TnK1vobvj8MRmyN2Y6ZgARj5HCtpMKg+YvjN2c8X39mplufWciP5TxNhOUaCLZT7NNGXnArjg6ZTrgwdprj7qg=="
    # data = {
    #     "from": from_address,
    #     "to": to_address,
    #     "memo": "123",
    #     "script_type": "P2PKH",
    # }
    # un_script = f'{sign_data(sk, data)} {from_address}'
    # data["script_pubkey"] = f'OP_DUP OP_HASH {hash_256(from_address)} OP_EQUALVERIFY OP_CHECKSIG'
    # ret = validate_script(un_script, data)
    # print(ret)

    p2sh_data = {
        "from": from_address,
        "to": to_address,
        "memo": "123",
        "script_type": "P2SH",
    }

    red_script = f'2 {one[0]} {two[0]} {from_address} 3 OP_CHECKMULTISIG'
    unlock_script = f'{sign_data(one[1], p2sh_data)} {sign_data(two[1], p2sh_data)} {red_script}'

    p2sh_data["script_hash"] = f"OP_HASH {hash_256(red_script)} OP_EQUALVERIFY"

    ret = validate_script(red_script, p2sh_data, unlock_script)
    print(ret)