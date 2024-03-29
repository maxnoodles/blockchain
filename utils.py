from pprint import pprint
from typing import Union

import base58
import hashlib
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path

import ecdsa

CURVE = ecdsa.SECP256k1
NODE_ADDRESS_PATH = "files/host_address.txt"
KEY_PATH = "files/key.txt"


def validate_script(lock_script, script_type, in_data):
    tmp_data = deepcopy(in_data)
    unlock_script = tmp_data.pop("sig")
    match script_type:
        case "P2SH":
            """
            两个脚本经由两步实现组合。 首先，将 unlock_script 与 lock_script 比对以确认其与哈希是否匹配
            <2 PK1 PK2 PK3 3 OP_CHECKMULTISIG> HASH <redeem scriptHash> OP_EQUALVERIFY
            假如兑换脚本哈希匹配，解锁脚本自行执行以解锁兑换脚本
            <Sig1> <Sig2> 2 PK1 PK2 PK3 3 OP_CHECKMULTISIG
            """
            lock_script = lock_script.lstrip("OP_HASH")
            redeem_hash = hash_256(tmp_data["redeem_script"])
            return eval_script(f"{redeem_hash} {lock_script} {unlock_script}", tmp_data)
        case "P2PKH" | "P2PK":
            # OP_DUP OP_HASH160 ab68025513c3dbd2f7b92a94e0581f5d50f654e7 OP_EQUALVERIFY OP_CHECKSIG
            return eval_script(f"{unlock_script} {lock_script}", tmp_data)
    return False


def build_multi_script(pk_list, sig_nums):
    script = f"{sig_nums} {' '.join(pk_list)} {len(pk_list)} OP_CHECKMULTISIG"
    return script, hash_256(script)


def eval_script(script, data):
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
                if not validate_sig_data(pubk, sig, data):
                    return False
            case "OP_CHECKMULTISIG":
                # 检测多重签名
                # <Signature B> <Signature C> 2 <Public Key A> <Public Key B> <Public Key C> 3 CHECKMULTISIG
                pk_nums = stack.pop()
                pk_lists = [stack.pop() for _ in range(int(pk_nums))]
                sig_nums = stack.pop()
                sig_lists = [stack.pop() for _ in range(int(sig_nums))]
                if not validate_multi_sign(pk_lists, sig_lists, data):
                    return False
            case str() as s:
                stack.append(s)

    return True if not stack else False


def validate_multi_sign(pk_lists, sig_lists, out_data):
    success_count = 0
    for sig in sig_lists:
        for pk in pk_lists:
            if validate_sig_data(pk, sig, out_data):
                success_count += 1
    if success_count == len(sig_lists):
        return True
    return False


def time_format(_time: datetime, _format="%Y-%m-%d %H:%M:%S.%f"):
    return _time.strftime(_format)


def hash_256(s, b58=True):
    data = hashlib.sha256(s.encode())
    if b58:
        return base58.b58encode(data.digest()).decode()
    else:
        return data.hexdigest()


def build_sig(data, sk_list, pk_str):
    sig_str = " ".join((sign_data(sk, data) for sk in sk_list))
    return " ".join([sig_str, pk_str])


def build_simple_vin(txid, vout):
    return {"txid": txid, "vout": vout}


def sign_data(secret_key: str, data: Union[dict, str]):
    sig_byte = build_to_sig_byte(data)
    signature = sign_byte(secret_key, sig_byte)
    return signature


def sign_byte(secret_key, sig_byte):
    _sk = base58.b58decode(secret_key.encode())
    sk = ecdsa.SigningKey.from_string(_sk, curve=CURVE)
    signature = base58.b58encode(sk.sign(sig_byte)).decode()
    return signature


def validate_sig_data(public_key, signature, data):
    to_sig_byte = build_to_sig_byte(data)
    return validate_sig_byte(public_key, signature, to_sig_byte)


def build_to_sig_byte(data: Union[dict, str]):
    match data:
        case dict() | list():
            return json.dumps(data, sort_keys=True).encode()
        case str():
            return data.encode()
        case _:
            raise ValueError(f"{data} 类型错误")


def validate_sig_byte(public_key: str, sign: str, to_sig_byte: bytes):
    public_key = base58.b58decode(public_key.encode())
    signature = base58.b58decode(sign.encode())
    vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    try:
        return vk.verify(signature, to_sig_byte)
    except:
        return False


def generate_ecdsa_keys(write_file=True):
    # https://github.com/tlsfuzzer/python-ecdsa
    _sk = ecdsa.SigningKey.generate(curve=CURVE)  # this is your sign (private key)
    vk = _sk.get_verifying_key()  # this is your verification key (public key)
    pk = base58.b58encode(vk.to_string()).decode()
    sk = base58.b58encode(_sk.to_string()).decode()
    if write_file:
        with open(KEY_PATH, "a") as f:
            f.write(json.dumps({hash_256(pk): (pk, sk)}) + "\n")
    return pk, sk


def check_address_in_script(pk, script):
    if pk in script or hash_256(pk) in script:
        return True
    return False


def get_host_address(host):
    if not host:
        return hash_256(generate_ecdsa_keys(write_file=False)[0])
    p = Path(NODE_ADDRESS_PATH)
    addr_map = {}
    if not p.exists():
        p.touch()
    else:
        with p.open("r") as f:
            addr_map = json.loads(f.read())
    if host not in addr_map:
        addr_map[host] = hash_256(generate_ecdsa_keys()[0])
        with p.open("w") as f:
            f.write(json.dumps(addr_map))
    return addr_map[host]


def get_pk_sk_map():
    addr_map = {}
    with open(KEY_PATH, "r") as f:
        for row in f.readlines():
            addr_map.update(json.loads(row))
    return addr_map


def build_script_pubkey(addr, script_type):
    match script_type:
        case "P2PK":
            # <PubKey> OP_CHECKSIG
            script_pubkey = f"{addr} OP_CHECKSIG"
        case "P2SH":
            # OP_HASH <PubKeyHash> OP_CHECKSIG
            script_pubkey = f"OP_HASH {addr} OP_EQUALVERIFY"
        case "P2PKH":
            # OP_DUP OP_HASH <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
            script_pubkey = f"OP_DUP OP_HASH {addr} OP_EQUALVERIFY OP_CHECKSIG"
        case _:
            raise ValueError(f"{script_type} error")
    return script_pubkey
