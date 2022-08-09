# Python 实现简单比特币



### 简介

项目地址 https://github.com/maxnoodles/blockchain 
实现了 《精通比特币中》书中的以下特性。

- 交易
- UTXO
- 区块链
- 非对称加密的密钥与地址
- 比特币交易脚本
- 简单的挖矿算法
- 简单的多节点共识

本文章从比特币最核心的 交易功能 作为切入点，一步一步到最后搭建一个区块链。



### 1. 交易

#### 1.1 普通交易

一个最简单的交易函数如下

```python
def new_transaction(_from, to, value):
    return {
        "from": _from,
        "to": to,
        "value": value
    }
    
new_transaction("alice", "bob", 50)
```

最后的函数调用表示 alice 向 bob 转了 50 个 btc (比特币)。

这个简单的交易函数无法满足很多现实的问题，例如：想要给别人比特币，那需要先证明自己有比特币，而 alice 的比特币如何来的呢？ 

答： 创币交易，也称为挖矿

```python
def mine():
    return new_transaction("0", "alice", 50)

mine()
```

约定 from 为 "0" 的是一个创币交易，即挖矿所产生的奖励交易。但是这并非能凭空生成的，需要付出服务器的计算资源，后续的工作量证明算法会讲到。



目前已经解决了 btc 的由来，还要解决一个问题，bob 如何确定找到 alice 有50个比特币用来交易，而不是空头支票，最简单的方法就是让 bob 看到 alice 的那笔创币交易。

所以我们修改 new_transaction 函数给每笔交易增加一个全局唯一的 txid (transaction_id) 来代表一笔交易。

```python
import json
import hashlib
import base58

def new_transaction(_from, to, value):
    trans = {
        "from": _from,
        "to": to,
        "value": value
    }
    trans["txid"] = _hash(trans)
    return trans

def _hash(data):
    # 先使用 json.dumps 将字典转换为字符串
    dump_data = json.dumps(data, sort_keys=True)
    sha_data = hashlib.sha256(dump_data.encode())
    # 使用 base58 对 sha256 算法获取的摘要进行编码，这样可以大幅缩小摘要的长度
    return base58.b58encode(sha_data.digest()).decode()

def mine():
    return new_transaction("0", "alice", 50)    

to_alice = mine()
"""
{
	'txid': 'j9iPoqLEynzx3vzymUsa2BqVGn4cyT7expv4EUUjvwH'
	'from': '0',
	'to': 'alice',
	'value': 50,
}
"""

to_bob = new_transaction(to_alice["txid"], "bob", 50)
"""
{
	'from': 'j9iPoqLEynzx3vzymUsa2BqVGn4cyT7expv4EUUjvwH',
	'to': 'alice',
	'value': 50,
	'txid': '6bezM4uy5R9zVFa6nN2oG6X7iTKsyWgsLVKL2Ksw2RtD'
}
"""
```

在 alice 和 bob 的交易数据结构中， from 字段从 alice 变成了创币交易的 txid。

这样 bob 就可以从 txid 中找到创币交易，再从创币交易的 to 字段得知 alice 确实收到了一笔 50 个比特币的交易。



那现在 bob 就可以相信这笔交易了吗？

答：还不行，因为 bob 不知道创币交易的 to 字段的 alice 和与他交易的 alice 是不是同一个人，有可能交易的 alice 只是恰好引用了一个 to 字段同名的创币交易。



#### 1.2 公钥与私钥

只要名字相同就能随便引用他人的交易，窃取他人的比特币，这样交易毫无安全性保证。此时我们需要一个可以证明身份，但是又不暴露身份的算法。

非对称加密算法是一个成熟的解决方案，这类算法提供一个公钥和私钥，还有一对签名和验证签名的函数。

公钥与私钥一一对应，私钥使用签名函数对数据进行签名，公钥能使用验证签名函数来验证。

这样交易接收方从一个昵称变为一个公钥。而发起方在交易时，需要提供对所引用交易的签名， 我们约定签名的数据为所引用交易的 txid 。

```python
import base58
import ecdsa

CURVE = ecdsa.SECP256k1
# 生成公钥和私钥
def generate_ecdsa_keys():
    # https://github.com/tlsfuzzer/python-ecdsa
    _sk = ecdsa.SigningKey.generate(curve=CURVE)  # this is your sign (private key)
    vk = _sk.get_verifying_key()  # this is your verification key (public key)
    pk = base58.b58encode(vk.to_string()).decode()
    sk = base58.b58encode(_sk.to_string()).decode()
    return pk, sk

# 使用私钥签名数据
def sign_data(secret_key, to_sig_data: str):
    _sk = base58.b58decode(secret_key.encode())
    sk = ecdsa.SigningKey.from_string(_sk, curve=CURVE)
    signature = base58.b58encode(sk.sign(to_sig_data.encode())).decode()
    return signature

# alice 的公私钥
a_pk, a_sk = generate_ecdsa_keys()
#a_pk = '3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh'
#a_sk = '7Wtwfzt5kyz6AqKorXqPNc9ifaLzVCAWZf5o4h2jpcSK'


b_pk, b_sk = generate_ecdsa_keys()
#b_pk = 'TPzyg9rDVMwvfHvmm5jThTZFLv1LAMQy8BPMVneSVVKRgne18G54vB6QKH2C8V8doCJP5KRhukGks82kYHLF7FK'
#b_sk = 'H2RtiRNZYKw8tH1kKu1Z4iHNn9wwX2KHBWGE54sJcGnT'

def new_transaction(_from, to, value, sig):
    trans = {
        "from": _from,
        "sig": sig,
        "to": to,
        "value": value
    }
    trans["txid"] = _hash(trans)
    return trans

def mine(pk):
    return new_transaction("0", pk, 50, '') # 创币交易不需要签名

# 创币交易传入 alice 的 pk
mine_trans = mine(a_pk)
"""
{
	'txid': '2LCXgoadt5LVBzbuaMfwzAoDVZEpqkTyaZfdRDTfFCra',
	'from': '0',
	'sig': '',
	'to': '3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh',
	'value': 50
}
"""

# 和 bob 的交易需要引用 mine_trans 的 txid ，先对其签名
m_txid = mine_trans["txid"]
# 使用私钥对数据进行签名
a_sig = sign_data(a_sk, m_txid)

# alice 向 bob 的交易
new_transaction(m_txid, b_pk, 50, a_sig)
"""
{
	'txid': '7soXwyxdMircXrEeiBY2Ds6edK8BYMSuN2duPd42cgEb',
	'from': '2LCXgoadt5LVBzbuaMfwzAoDVZEpqkTyaZfdRDTfFCra',
	'sig': 'QVk8DRoBzfhDqXDg8wAkYcoCe11FQgaDowmEmxkusWtN1exGMysF3scwpLhNJZ8rGj3bwK9h2BDqwf4j66wpU31',
	'to': 'TPzyg9rDVMwvfHvmm5jThTZFLv1LAMQy8BPMVneSVVKRgne18G54vB6QKH2C8V8doCJP5KRhukGks82kYHLF7FK',
	'value': 50
}
"""
```



#### 1.3 比特币交易脚本

前面我们约定使用 private_key 对 txid 进行签名生成 sig 字段。

但是比特币的交易验证并非静态不变的，而是通过脚本语言的执行来实现的。脚本语言允许表达几乎无限的各种条件，使得比特币成为一种“可编程的货币” 。

使用脚本时，像上面 alice 的创币交易，"约定使用 private_key 对 txid 进行签名生成 sig 字段" 这个行为可以缩写成一个字符串 `OP_CHECKSIG` 增加再 to 字段的公钥后面。

to 字段改名为 `script_pubkey`  ，因为它不再表示一个公钥的接口地址，而是一段脚本，

再增加一个脚本类型字段 `script_type`，值为 `P2PK` (pay to public key )，用户只要传入公钥，代码可以根据类型来生成对应的脚本。

```python
def new_transaction(_from, script_pubkey, value, sig, script_type):
    trans = {
        "from": _from,
        "sig": sig,
        "script_pubkey": script_pubkey,
        "script_type": script_type,
        "value": value
    }
    if script_type == 'p2pk':
        trans["script_pubkey"] = f'{script_pubkey} OP_CHECKSIG' 
    trans["txid"] = _hash(trans)
    return trans


def mine(script_pubkey, script_type):
    return new_transaction("0", script_pubkey, 50, '', script_type)  # 创币交易不需要签名


# alice 的创币交易
mine_trans = mine(a_pk, 'p2pk')
"""
{
	'from': '0',
	'script_pubkey': '3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh OP_CHECKSIG',
	'script_type': 'p2pk',
	'sig': '',
	'txid': 'DHkLcgD2bhRh5n8w8CUfN3t91cjCgzkuHDki58HDVvUd',
	'value': 50
}
"""


# alice 向 bob 的交易
m_txid = mine_trans["txid"]
a_sig = sign_data(a_sk, m_txid)
new_transaction(m_txid, b_pk, 50, a_sig, 'p2pk')
"""
{
	'from': 'DHkLcgD2bhRh5n8w8CUfN3t91cjCgzkuHDki58HDVvUd',
	'script_pubkey': 'TPzyg9rDVMwvfHvmm5jThTZFLv1LAMQy8BPMVneSVVKRgne18G54vB6QKH2C8V8doCJP5KRhukGks82kYHLF7FK OP_CHECKSIG',
	'script_type': 'p2pk',
	'sig': '5ZeVBZdGfhzt9jZ562gGGgnP5bidzz3hfNaGypYR2uJAmm7tgduueukmAqCgYbiQRL9m4C67LfRQ4AXiwHJAnD2e',
	'txid': '7swwNNeBXC484YVTBBkakZGCRK8ZoWYHD12fuwVqxts6',
	'value': 50
}
"""

```

如果你愿意，完全可以自由定义签名函数和脚本类型，写出各种各样的方法来交易规则。



接下来介绍一下比特币脚本是如何执行的。

只有私钥才能提供签名才解锁被引用的交易，所以称 script_pubkey 为锁定脚本， 而 sig 为解锁脚本。

将交易的 sig 字段使用一个空格拼接到引用交易的 script_pubkey 后面，变成像  <sig>  <script_pubkey> 这样的格式。

例如上面 alice 引用创币交易，那完整的脚本就是，将和 bob 交易的 sig 字段 + " " + 创币交易的 script_pubkey  ，如下

```
2uVD7oz6de2JcwnCg4ZDSBxSfBWD8aukFcW97UbASJeCHE9kmE6o8GwFQRTvfdWXUEfgHAQR8WHjjEFyyQXezT6U 3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh OP_CHECKSIG
```

以上就是一个最简单的脚本，接下来看看解析脚本的代码

比特币脚本是一种基于栈的语言。

将脚本按空格分割后压入栈中，根据关键词取出栈中元素进行计算，代码如下

```python
def eval_script(script: str, data: str):
    """
    
    :param script: 比特币脚本
    :param data: 签名的原始数据
    """
    stack = []
    # 通过空格分离脚本的各部分 (合成脚本的时候就是使用空格拼接的)
    tax_list = script.strip().split()
    for tax in tax_list:
        match tax:
            # 检测到 OP_CHECKSIG 关键词，弹出栈顶2个元素，其中第一个是公钥，第二个是签名
            case "OP_CHECKSIG":
                # <sig> <pubk> OP_CHECKSIG
                pubk = stack.pop()
                sig = stack.pop()
                # 调用函数验证签名
                if not validate_sig_data(pubk, sig, data):
                    return False
            case str() as s:
                stack.append(s)

    return True if not stack else False


# 传入公钥，签名和 签名前的数据 来验证签名是否正确。
def validate_sig_data(public_key: str, sign: str, to_sig_data: str):
    public_key = base58.b58decode(public_key.encode())
    signature = base58.b58decode(sign.encode())
    vk = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    try:
        return vk.verify(signature, to_sig_data.encode())
    except:
        return False
    
script = '2uVD7oz6de2JcwnCg4ZDSBxSfBWD8aukFcW97UbASJeCHE9kmE6o8GwFQRTvfdWXUEfgHAQR8WHjjEFyyQXezT6U 3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh OP_CHECKSIG'
data = 'DHkLcgD2bhRh5n8w8CUfN3t91cjCgzkuHDki58HDVvUd'  # 创币交易的 txid
eval_script(script, data)  # True
```



#### 1.4 交易多个输入和多个输出

通过引用交易的方法，每次交易的数额并不能由自己决定，只能使用所引用的交易的数额，非常的不方便，所以引入了多输入和多输出。

多输入可以引用多笔交易来筹齐一个比较大的金额。

多输出也可以用于给多地址转账，或者交易剩余的找零等。

将输入相关信息迁移到到 vin 列表中，因为不会与外层的 txid 字段命名冲突，所以 from 字段更名更能表达准确性的 txid  (引用的 txid)，输出相关的信息迁到 vout 列表中。代码变化如下：

```python
def build_one_vin(txid: str, vout: str, sig: str = None):
    """
    构建一个交易输入
    :param txid: 引用的交易id
    :param vout: 引用交易的第几个输出
    :param sig: 签名
    :return:
    """
    _in = {
        "txid": txid,
        "vout": int(vout),
    }
    if sig:
        _in["sig"] = sig
    return _in


def build_one_vout(script_pubkey, value, script_type):
    """
    构建一个交易输出
    :param addr: 哈希地址
    :param value: 数量
    :param script_type: 脚本类型
    :return:
    """
    out = {
        "script_type": script_type,
        "value": value,
    }
    if script_type == 'p2pk':
        out["script_pubkey"] = f'{script_pubkey} OP_CHECKSIG' 
    return out


def new_transaction(txid_in_list: list, out_list: list):
    """
    :param txid_in_list: [(txid, vout, sig)]
    :param out_list: [(script_pubkey, value, script_type)]
    """
    vin_list = [build_one_vin(*i) for i in txid_in_list]
    vout_list = [build_one_vout(*i) for i in out_list]
    trans = {
        "vin": vin_list,
        "vout": vout_list
    }
    trans["txid"] = _hash(trans)
    return trans


def mine(script_pubkey, script_type):
    # 修改成新的调用方式
    return new_transaction([("0", 0)], [(script_pubkey, 50, script_type)])


# alice 的创币交易
m_trans = mine(a_pk, 'p2pk')
"""
{
	'txid': '7imB16XkZ9i4wkoWvKtd1DG1qXAbmwdPL948W5nYinXw',
	'vin': [{
		'txid': '0',
		'vout': 0
	}],
	'vout': [{
		'script_pubkey': '3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh OP_CHECKSIG',
		'script_type': 'p2pk',
		'value': 50
	}]
}
"""

# alice 向 bob 的交易
m_txid = m_trans["txid"]
a_sig = sign_data(a_sk, m_txid)
vin = [(m_txid, 0, a_sig)]
vout = [(b_pk, 50, 'p2pk')]

# 向 bob 的交易
new_transaction(vin, vout)
"""
{
	'txid': '2qHqsZZGuhypc71s1wRUMEUssBVQtXyNDRqt3dWjY6GE',
	'vin': [{
		'sig': '3N4iA1CtRv2EYmrQoC65aJft9BzH9Zmto78FRHGHcGNFHquU3e5kvzXKhJSAZWNFTZ46KKZAZq5FkENXntaueiAJ',
		'txid': '7imB16XkZ9i4wkoWvKtd1DG1qXAbmwdPL948W5nYinXw',
		'vout': 0
	}],
	'vout': [{
		'script_pubkey': 'TPzyg9rDVMwvfHvmm5jThTZFLv1LAMQy8BPMVneSVVKRgne18G54vB6QKH2C8V8doCJP5KRhukGks82kYHLF7FK OP_CHECKSIG',
		'script_type': 'p2pk',
		'value': 50
	}]
}

"""
```



#### 1.5 UTXO

每一表交易的 from 都是另外一笔交易的 txid，交易的接收方如何验证所引用的 txid 是有效的呢？而且接收方还需要拿到引用交易的 script_pubkey 用于配合新交易的签名进行验证。

答：到 utxo 中查询，utxo 包含了所有未被引用的交易输出，自然也包括输出的 script_pubkey 。

`utxo` 全称 `unspent transaction output` 未花费交易集合，每创建一次交易都要调整 utxo 的数据，将引用的交易的 vout 删除，新交易的 vout 加入，特殊情况是创币交易没有引用的交易，所以不需要删除引用的 vout ，只需要加入新交易的 vout 即可。

数据结构如下，一个全局的嵌套字典。最外层 key 为未被引用交易的 txid，

内层 key 为 vout 索引值，value 为 vout 具体的值

代码如下：

```python
from collections import defaultdict

UTXO = defaultdict(dict)

def adjust_UTXO(trans):
    """
    调整 UTXO
    :param trans: 一个交易
    """
    txid = trans["txid"]
    # UTXO 中删除 vin
    for vin in trans["vin"]:
        in_txid, out = vin["txid"], vin["vout"]
        if in_txid != "0":   # 创币交易引用的 txid 是 "0"，无中生有的交易，不可能在 utxo 中
            if not UTXO[in_txid]:
                UTXO.pop(in_txid)
    # UTXO 中增加 vout
    for idx, vout in enumerate(trans["vout"]):
        UTXO[txid][idx] = vout
        
        
def new_transaction(txid_in_list: list, out_list: list):
    vin_list = [build_one_vin(*i) for i in txid_in_list]
    vout_list = [build_one_vout(*i) for i in out_list]
    trans = {
        "vin": vin_list,
        "vout": vout_list
    }
    trans["txid"] = _hash(trans)
    
    # 维护 UTXO
    adjust_UTXO(trans)
    return trans

# alice 的创币交易
m_trans = mine()
m_txid = m_trans["txid"]
print(UTXO)
"""
{
	'7imB16XkZ9i4wkoWvKtd1DG1qXAbmwdPL948W5nYinXw': {
		0: {
			'script_pubkey': '3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh OP_CHECKSIG',
			'script_type': 'p2pk',
			'value': 50
		}
	}
}
"""

# alice 向 bob 的交易
a_sig = sign_data(a_sk, m_txid)
vin = [(m_txid, 0, a_sig)]
vout = [(b_pk, 50, 'p2pk')]
new_transaction(vin, vout)
print(UTXO)
# alice 创币交易的 txid 被引用以后从 utxo 中删除了，而新的 txid 加入到 utxo 字典中
"""
{
	'7z6dYS2iBm9K7Yue2CJLuuCH6xXb2P1JfFHn4QvjJpdq': {
		0: {
			'script_type': 'p2pk',
			'value': 50,
			'script_pubkey': 'TPzyg9rDVMwvfHvmm5jThTZFLv1LAMQy8BPMVneSVVKRgne18G54vB6QKH2C8V8doCJP5KRhukGks82kYHLF7FK OP_CHECKSIG'
		}
	}
}
"""


# 有了 utxo, 我们可以轻松找到引用交易的输出，终于可以把验证签名的代码加入到 new_transaction 函数中了
def new_transaction(txid_in_list: list, out_list: list):
    vin_list = [build_one_vin(*i) for i in txid_in_list]
    vout_list = [build_one_vout(*i) for i in out_list]
    # 验证输入列表，错误直接抛出异常
    is_valid_vin_list(vin_list)

    trans = {
        "vin": vin_list,
        "vout": vout_list
    }
    trans["txid"] = _hash(trans)
    
    # 维护 UTXO
    adjust_UTXO(trans)
    return trans

def is_valid_vin_list(self, vin_list):
    if self.is_mine_trans(vin_list):
        # 创币交易，跳过
        return True

    for vin in vin_list:
        txid, out_idx = vin["txid"], vin["vout"]
        if txid not in self.UTXO:
            raise ValueError(f"txid {txid} 无效")
        if out_idx not in self.UTXO[txid]:
            raise ValueError(f"txid {txid} 使用的 vout {out_idx} 无效")

        # 验证解锁脚本
        out_data = self.UTXO[txid][out_idx]
        if not eval_script(
            f'{out_data["script_pubkey"]} {vin["sig"]}',
            vin["txid"],
        ):
            raise ValueError(f"{txid} script result False")

def is_mine_trans(vin_list):
    return len(vin_list) == 1 and vin_list[0]["txid"] == "0"

```



### 2. 区块

在比特币区块链上，单位并非一笔交易，而是由 多笔交易组成的一组交易，称为区块。

类似与批处理的概念，如果每个交易都到所有节点共识的话，就变成每一笔交易都要等待上一笔交易成功才能继续交易，效率非常差，使用区块能提升效率，一次共识就是一批交易而非一个。

最简单的区块 就是对整批交易做一下哈希，然后增加一个唯一的区块索引字段 Index 。

```python
def new_block(trans_list):
    """创建区块，传入交易列表"""
    return {"transactions": trans_list, "index": _hash(trans_list)}
	

# 创币交易
m_trans = mine()
m_txid = m_trans["txid"]
# alice 向 bob 的交易
a_sig = sign_data(a_sk, m_txid)
vin = [(m_txid, 0, a_sig)]
vout = [(b_pk, 50, 'p2pk')]
b_trans = new_transaction(vin, vout)

# 将两笔交易打包成一个区块
new_block([m_trans, b_trans])    
"""
{
	'index': '2LFb17UNxtZFQSRB8J2sM7Vpbn7szmgfrfXaKEL3xJhy',
	'transactions': [{
			'txid': '7imB16XkZ9i4wkoWvKtd1DG1qXAbmwdPL948W5nYinXw',
			'vin': [{
				'txid': '0',
				'vout': 0
			}],
			'vout': [{
				'script_pubkey': '3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh '
				'OP_CHECKSIG',
				'script_type': 'p2pk',
				'value': 50
			}]
		},
		{
			'txid': 'AbTRmmMJ6AG7UPHwWdwKAPBapsqgtJzxJg6RryBhLkBa',
			'vin': [{
				'sig': '4bWbkK8sh4oyLJTMQeCUGTiwV6iU8o4zufCY15R4rgiK8e8FvQ87RMtWDgsc9x34YU4xg44nm87Av17SCJa86F9J',
				'txid': '7imB16XkZ9i4wkoWvKtd1DG1qXAbmwdPL948W5nYinXw',
				'vout': 0
			}],
			'vout': [{
				'script_pubkey': 'TPzyg9rDVMwvfHvmm5jThTZFLv1LAMQy8BPMVneSVVKRgne18G54vB6QKH2C8V8doCJP5KRhukGks82kYHLF7FK '
				'OP_CHECKSIG',
				'script_type': 'p2pk',
				'value': 50
			}]
		}
	]
}
"""
```

生成区块的行为看起来很简单，任何节点都能大量得生成区块，如何向别人证明你的区块是可信任的？

答:  哈希链接 +工作量证明算法



#### 2.1 哈希链接

为区块生成哈希值时。将上一个区块的 哈希值 也添加在哈希内容中（创世区块不需要，因为没有上一个）。

这样每个区块在其哈希中都包含之前的区块的哈希，构成了一个链。

每个区块的哈希值保护了他之前的所有数据，如果前面区块有数据被更改，被修改的区块哈希值会改变，导致和后续哈希链条断开。



实现上使用一个 prvious_hash 来指向上一个哈希，对区块做哈希时会加上这个字段。

```python
BlockChain = []

# 我们将上面2个交易拆成2个区块演示一下
# 假设 alice 的创币交易就是创世区块，此时 prvious_hash 为 0
def new_block(trans_list):
    prv_hash = BlockChain[-1]["index"] if BlockChain else ''
    block = {"transactions": trans_list, "previous_hash": prv_hash}
    block["index"] = _hash(block)
    BlockChain.append(block)
    return block

new_block([m_trans])
print(BlockChain)
"""
[{
	'previous_hash': '',
	'index': '2HVFNJKqt6FT82p3YNtv558NMRdCynB9hVE1iz43Ypqx',
	'transactions': [{
    	'txid': '7imB16XkZ9i4wkoWvKtd1DG1qXAbmwdPL948W5nYinXw',
		'vin': [{
			'txid': '0',
			'vout': 0
		}],
		'vout': [{
			'script_type': 'p2pk',
			'value': 50,
			'script_pubkey': '3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh OP_CHECKSIG'
		}],
	}]
}]

"""

new_block([b_trans])
print(BlockChain)
# 有2个区块，第二个区块的 previous_hash 等于第一个区块的 index
"""
[{

	'previous_hash': '',
	'index': '2HVFNJKqt6FT82p3YNtv558NMRdCynB9hVE1iz43Ypqx'
	'transactions': [{
    	'txid': '7imB16XkZ9i4wkoWvKtd1DG1qXAbmwdPL948W5nYinXw'
		'vin': [{
			'txid': '0',
			'vout': 0
		}],
		'vout': [{
			'script_type': 'p2pk',
			'value': 50,
			'script_pubkey': '3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh OP_CHECKSIG'
		}],
	}],
}, {
	'previous_hash': '2HVFNJKqt6FT82p3YNtv558NMRdCynB9hVE1iz43Ypqx',
	'index': 'Fo8poMPrtDK1LBmDCvPe9uwySvcT1csAv8cnstETboh1',
	'transactions': [{
    	'txid': 'FJiVFwDNkW61r8FBhsVk8YUX3f3uvCmWYah8ebUxNzC7'
		'vin': [{
			'txid': '7imB16XkZ9i4wkoWvKtd1DG1qXAbmwdPL948W5nYinXw',
			'vout': 0,
			'sig': '3qY1wGuFxS2mYJW6idHvzktSSReWpJRVteaQLgi5f3UEfMSFwrACpqrfb7LJyv5z3L2uvwxjiPSjPY4Hmbxuy9UY'
		}],
		'vout': [{
			'script_type': 'p2pk',
			'value': 50,
			'script_pubkey': 'TPzyg9rDVMwvfHvmm5jThTZFLv1LAMQy8BPMVneSVVKRgne18G54vB6QKH2C8V8doCJP5KRhukGks82kYHLF7FK OP_CHECKSIG'
		}],
	}],
}]
"""

```

如果一次哈希每个区块，并 previous_hash 等于与上一个区块的 index ，那说明每一个区块都没有被串改。

但是，如果攻击者从某一个区块开始攻击，像 git 的分支一样，伪造后面所有的区块，也能达成篡改的目的。原因是伪造区块的代价太低了，如果只是简单的哈希作为证明，攻击者一秒钟内就能伪造整个区块链。



#### 2.2 工作量证明算法

简单来说，工作量证明算法就是一个 `增加生成区块的难度` 的算法，这样每生成一个有效的区块，攻击者攻击的时候就要付出生成有效区块一样的资源。这样当生成的区块足够多，攻击者的投入大到无法覆盖收益时，便会发起攻击。

算法大概思路如下：

在区块之中增加一个随机数，然后对区块进行哈希，直到这个区块的哈希以指定数量的 0 开头。一旦 CPU 的耗费算力所获的的结果满足工作证明，那么这个区块将不再能被更改，除非重新完成之前的所有工作量。随着新的区块不断被添加进来，改变当前区块即意味着说要重新完成所有其后区块的工作。

当使用某个 随机数 计算得到满足条件的值以后，这个哈希值就是区块的哈希值，而随机数被存放在字段 proof 中，在验证区块哈希者的时候，就需要取出随机数来验证。

算法代码如下：

```python
def proof_of_work(block: dict):
    """
    简单的工作量证明算法
    找到一个数，使得区块的hash前4位为0
    :param block: 区块
    :return:
    """
    # 工作量证明--->穷举法计算出特殊的数
    block_hash = _hash(block)
    proof = 0
    while True:
        ret, hash_val = valid_proof(proof, block_hash)
        if ret:
            return proof, hash_val
        proof += 1

        
def valid_proof(proof, block_hash) -> (bool, str):
    """
    验证工作量证明，计算出的hash是否正确
    对上一个区块的proof和hash与当期区块的proof做sha256运算、
    :param proof: 当前区块的随机数（工作量）
    :param block_hash: 本区块的 hash
    """
    guess = f"{proof}{block_hash}"
    guess_hash = _hash(guess, b58=False)
    return guess_hash[:4] == "0000", guess_hash


def new_block(trans_list):
    prv_hash = BlockChain[-1]["index"] if BlockChain else ''
    block = {"transactions": trans_list, "previous_hash": prv_hash}
    block["proof"], block["index"] = proof_of_work(block)
    BlockChain.append(block)
    return block

new_block([m_trans])
# index 字段的值开头的4个0
"""
{
	'previous_hash': 'B6JzMyA8XSU5nBpFj8cNVBeb5KW6sYzC9yTPSksLVWiU',
	'proof': 1840,
	'index': '0000b18b7e24fc09ab46327f9968762fd1a269d81d20963369aedbcc557e9f97'
	'transactions': [{
		'vin': [{
			'txid': '0',
			'vout': 0
		}],
		'vout': [{
			'script_type': 'p2pk',
			'value': 50,
			'script_pubkey': '3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh OP_CHECKSIG'
		}],
		'txid': '7imB16XkZ9i4wkoWvKtd1DG1qXAbmwdPL948W5nYinXw'
	}],
}
"""
```



#### 2.3 默克尔树

有以下作用：

1.一个区块 99% 数据都是交易，每次计算工作量证明时，都需要对交易数据重复进行哈希计算。将交易数据构建默克尔树以后，可以只对默克尔树根节点的哈希值做哈希即可。

2.有的区块链节点只会保持区块的元数据(不包含交易数据)，当节点接收到一笔交易时，需要验证交易是否被修改过。

![微信图片_20220809142852](https://raw.githubusercontent.com/maxnoodles/picture_bed/master/img/202208091437753.jpg)

假设图中的 L4 就是一个交易，那只需要全节点(含有所有交易数据) 提供一个 [hash(L3), hash0, hash4] 这3个树节点的哈希值的值即可。然后通过下图的运算，与区块链节点区块的默克尔树值比较。相同则交易没有被修改过。

```python
hash(
	hash(
        hash0 + hash(
        	hash(L4) + hash(L3)
        ) 
    ) + hash4
) == proof
```

默克尔树的实现可以参考一下这个库，只有100来行代码 **https://github.com/Tierion/pymerkletools**



#### 2.4 补充字段

高度 height（目前区块链的长度）

时间戳 timestamp (开始生成区块的时间)

修改后代码如下:

```python
def new_block(trans_list):
    prv_hash = BlockChain[-1]["index"] if BlockChain else ''
    block = {
        "transactions": trans_list,
        "previous_hash": prv_hash,
        # 高度
        "height": len(BlockChain),
        # 时间戳
        "timestamp": time.time(),
    }
    block["proof"], block["index"] = proof_of_work(block)
    BlockChain.append(block)
    return block

"""
{
	'previous_hash': '3BtvYoRWRDVzXCRPKESvUnmGyY5FX7fYL2FuoHRAyMup',
	'height': 2,
	'timestamp': 1660027848.0836937,
	'proof': 50558,
	'index': '000004f7c1636c0a9e1fb523197d3e4e8577d9c71d8854e14b9c60c1e4dc4e24'
	'transactions': [{
		'vin': [{
			'txid': '0',
			'vout': 0
		}],
		'vout': [{
			'script_type': 'p2pk',
			'value': 50,
			'script_pubkey': '3D7f8Ku26a5LWoM9QzL4zft9QGuypCuLvgeeP4uenWmBXCHfFR3r2eb33q2oUqzBTLh3MV2Bp7wSj7XqjtSebjhh OP_CHECKSIG'
		}],
		'txid': '7imB16XkZ9i4wkoWvKtd1DG1qXAbmwdPL948W5nYinXw'
	}],

}
"""
```



### 3. server 服务

1.从本地区块链文件加载区块链数据，构建 UTXO。

2.加入比特币网络，代码中硬编码一个全节点的地址，所有节点上线时访问这个地址注册 IP和端口，并得到中包含其他节点的 IP和端口 的响应，将其他节点的地址加入到本地内存中。

3.定时同步其他节点的区块链，应用最长的那一条链，防止分叉。

4.定时将区块数据写入文件。
