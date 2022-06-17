import copy
import hashlib
import json
import logging
from collections import defaultdict
from pprint import pformat
import time
from pathlib import Path

import requests

from market import MerkleTools
from utils import validate_script, build_simple_vin


def hash_block(block):
    block_str = json.dumps(block, sort_key=True).encode()
    return hashlib.sha256(block_str).hexdigest()


class BlockChain:
    def __init__(self, host: str = None):
        self.current_transactions = []
        self.chain = []
        self.market_trees = []
        self.UTXO = defaultdict(dict)
        self.full_node = "127.0.0.1:5000"
        self.host = host
        self.nodes = {host} if host else set()
        self.file_name = f"./chain_file/{self.host.replace(':', '_')}_chain.txt"

    def init_block(self):
        return {
            # 高度
            "height": len(self.chain),
            # 时间戳
            "timestamp": time.time(),
            # 上一区块的 hash
            'previous_hash': self.last_block["index"] if self.chain else None,
            # 默克尔树根
            "market_root": self.market(self.current_transactions)
        }

    def market(self, trans_list):
        mt = MerkleTools()
        mt.add_leaf([i["txid"] for i in trans_list], True)
        mt.make_tree()
        self.market_trees.append(mt)
        root_value = mt.get_merkle_root()
        return root_value

    def new_block(self):
        """
        创建一个新区块加入到区块链中
        :return: 一个新区块
        """
        block = self.init_block()
        # proof 工作量证明的随机数
        # index 工作量运行的哈希值
        block["proof"], block["index"] = self.proof_of_work(block)

        block["transactions"] = copy.deepcopy(self.current_transactions)
        # 重新置空
        self.current_transactions = []
        # 将区块添加到区块链中，此时交易账本是空，工作量证明是空
        self.chain.append(block)
        return block

    @property
    def last_block(self):
        """
        :return: 区块链中最后一个区块
        """
        return self.chain[-1]

    def proof_of_work(self, block: dict):
        """
        简单的工作量证明算法
        找到一个数，使得区块的hash前4位为0
        :param block: 区块
        :return:
        """
        block_cp = copy.deepcopy(block)

        # 工作量证明--->穷举法计算出特殊的数
        block_hash = self.hash(block_cp)
        proof = 0
        while True:
            ret, hash_val = self.valid_proof(proof, block_hash)
            if ret:
                break
            proof += 1

        return proof, hash_val

    @staticmethod
    def hash(block):
        """
        使用SHA256哈希算法计算区块的哈希
        :param block: 区块
        :return: 区块hash
        """
        # sort_keys()：json解析后获得的字典将通过key排序，encode()进行utf-8编码，不然hashlib加密会报错
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    @staticmethod
    def valid_proof(proof, block_hash) -> (bool, str):
        """
        验证工作量证明，计算出的hash是否正确
        对上一个区块的proof和hash与当期区块的proof最sha256运算
        :param block_hash: 本区块的 hash
        :param proof: 当前区块的工作量
        """
        guess = f'{proof}{block_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000", guess_hash

    @property
    def height(self):
        return len(self.chain)

    @staticmethod
    def build_one_vin(txid: str, vout: str, sig: str = None, redeem_script: str = None):
        """
        构建一个交易输入
        :param txid: 引用的交易id
        :param vout: 应用交易的第几个输出
        :param sig: 签名
        :param redeem_script: 赎回脚本
        :return:
        """
        _in = {
            "txid": txid,
            "vout": vout,
        }
        if sig:
            _in["sig"] = sig
        if redeem_script:
            _in["redeem_script"] = redeem_script
        return _in

    @staticmethod
    def build_one_vout(addr, value, script_type):
        """
        构建一个交易输出
        :param addr: 哈希地址
        :param value: 数量
        :param script_type: 脚本类型
        :return:
        """
        assert script_type in ["P2PK", "P2PKH", "P2SH"]
        out = {"script_type": script_type, "value": value}
        match script_type:
            case "P2PK":
                # <PubKey> OP_CHECKSIG
                out["script_pubkey"] = f"{addr} OP_CHECKSIG"
            case "P2PKH":
                # OP_DUP OP_HASH <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
                out["script_pubkey"] = f"OP_DUP OP_HASH {addr} OP_EQUALVERIFY OP_CHECKSIG"
            case "P2SH":
                # OP_HASH <PubKeyHash> OP_CHECKSIG
                out["script_hash"] = f"OP_HASH {addr} OP_EQUAL"
        return out

    def new_transaction(self, txid_in_list: list[tuple[str, int, ...]], out_list: list[tuple[str, float, str]],
                        nlock_time=None):

        """
        创建一个新的交易，添加到我创建的下一个区块中
        :param txid_in_list: 输入数组
        :param out_list: 输出数组
        :param nlock_time: 交易级别的时间
        :return: 记录本次交易的区块索引
        """
        vin_list = [self.build_one_vin(*i) for i in txid_in_list]
        vout_list = [self.build_one_vout(*i) for i in out_list]

        # 小于 5 亿，解释成区块高度, 大于 5 亿为时间戳
        if nlock_time:
            if nlock_time < 500000000:
                if self.height < nlock_time:
                    raise ValueError(f"nlock_time 再指定的区块高度之前无效")
            else:
                if nlock_time < time.time():
                    raise ValueError(f"nlock_time 需要大于当前时间")

        in_value_sum = 0

        if len(vin_list) != 1 or vin_list[0]["txid"] == "0":
            # 创币交易，跳过
            pass
        else:
            for vin in vin_list:
                txid, out = vin["txid"], vin["vout"]
                if txid == '0':
                    continue
                if txid not in self.UTXO:
                    raise ValueError(f"txid {txid} 无效")
                if out not in self.UTXO[txid]:
                    raise ValueError(f"txid {txid} 使用的 vout {out} 无效")

                # 验证解锁脚本
                out = self.UTXO[txid][out]
                if not validate_script(
                        out["script_pubkey"],
                        out["script_type"],
                        vin,
                        vin.get("redeem_script")
                ):
                    raise ValueError("script result False")

                in_value_sum += self.UTXO[txid][out]["value"]

            out_value_sum = sum([i["value"] for i in vout_list])
            if in_value_sum < out_value_sum:
                raise ValueError("输入金额小于输出金额")

        trans = {
            "vin": vin_list,
            "vout": vout_list,
            "nlock_time": nlock_time or len(self.chain),
        }
        # todo 自动找零
        txid = self.hash(trans)
        trans["txid"] = txid

        if txid in self.UTXO:
            raise ValueError("此交易已经被保存在区块中")

        self.current_transactions.append(trans)
        self.adjust_UTXO(vin_list, vout_list, txid)
        # 广播到其他节点
        self.flood_trans(txid_in_list, out_list)

    def flood_trans(self, txid_in_list, out_list):
        for node in self.nodes:
            if node == self.host:
                continue
            try:
                data = {
                    "txid_in_list": txid_in_list,
                    "out_list": out_list
                }
                requests.post(f'http://{node}/transactions/new', json=data, timeout=5)
            except:
                pass

    def adjust_UTXO(self, vin_list, vout_list, txid):
        """
        调整 UTXO
        :param vin_list: 交易输入
        :param vout_list: 交易输出
        :param txid: 新生成的交易 id
        :return:
        """

        # UTXO 中删除 vin
        for vin in vin_list:
            in_txid, out = vin["txid"], vin["vout"]
            if in_txid != '0':
                self.UTXO[in_txid].pop(out)
        # UTXO 中增加 vout
        for idx, vout in enumerate(vout_list):
            self.UTXO[txid][idx] = vout

    def register_node(self, url):
        """
        添加新的节点进入区块链网络，本地运行只需要端口
        :param url: url
        """
        self.nodes.add(url)

    def valid_chain(self, chain) -> bool:
        """
        检验区块链是否是合法的
        1.检查区块链是否连续
        2.检查工作量证明是否正常
        :param chain: 区块链
        """
        i = 1
        while i < len(chain):
            prv_blocks, block = chain[i - 1], chain[i]
            # id 是连续的
            if prv_blocks["index"] != block["previous_hash"] or not self.valid_proof(block["proof"], block):
                return False
            i += 1
        return True

    def resolve_conflicts(self) -> bool:
        """
        确保区块链网络中每个网络节点存储的区块链都是一致的，通过长区块链替换短区块链实现
        :return: True 替换 False不替换
        """
        new_chain = None
        # 本地区块链的长度
        local_len = len(self.chain)

        for node in self.nodes:
            if node == self.host:
                continue
            # 访问节点的一个接口，拿到该接口的区块链长度和区块链本身
            try:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    resp_dict = response.json()
                    length = resp_dict['length']
                    chain = resp_dict['chain']

                    # 判断邻居节点发送过来的区块链长度是否最长且是否合法
                    if length > local_len and self.valid_chain(chain):
                        # 使用邻居节点的区块链
                        local_len = length
                        new_chain = chain
            except:
                # 节点没开机
                pass
        if new_chain:
            self.chain = new_chain
            return True
        return False

    def __str__(self):
        return pformat(chain.chain)

    def timing_sync(self):
        """
        定时同步
        :return:
        """
        while True:
            time.sleep(5)
            print("开始同步其他节点区块链")
            self.resolve_conflicts()
            print(self.chain)

    def file_sync(self):
        """
        定时同步
        :return:
        """
        while True:
            time.sleep(30)
            self.write_to_file()

    def write_to_file(self):
        print("开始写入节点")
        with open(self.file_name, "w") as f:
            for block in self.chain:
                txt = json.dumps(block, sort_keys=True)
                f.write(f"{txt}\n")

    def reload_by_file(self):
        if Path(self.file_name).exists():
            with open(self.file_name, 'r') as f:
                for row in f.readlines():
                    block = json.loads(row)
                    self.chain.append(block)
            print("从文件加载完成", self.chain)

    def init_nodes(self, host):
        if host == self.full_node:
            return
        try:
            data = {
                "nodes": list(self.nodes)
            }
            response = requests.post(f'http://{self.full_node}/nodes/register', json=data, timeout=5)
            if response.status_code == 200:
                resp_dict = response.json()
                total_nodes = resp_dict["total_nodes"]
                print(total_nodes)
                self.nodes.update(total_nodes)
        except Exception as e:
            logging.exception(e)
            # 节点没开机


if __name__ == "__main__":
    chain = BlockChain("127.0.0.1:5000")
    # chain.reload_by_file()
    _in = [("0", 0)]
    _out = [("6e571da347b66acfb7109629be894c06d8294482b4da701398405fe292c78474", 50, "P2PK")]
    for i in range(5):
        chain.new_transaction(_in, _out)
        chain.new_block()
    chain.write_to_file()
    print(chain)
