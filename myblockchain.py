import copy
import hashlib
import json
from pprint import pprint, pformat
from time import time

import requests

from market import MerkleTools


def hash_block(block):
    block_str = json.dumps(block, sort_key=True).encode()
    return hashlib.sha256(block_str).hexdigest()


class BlockChain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.market_trees = []

    def init_block(self):
        return {
            # 高度
            "height": len(self.chain),
            # 时间戳
            "timestamp": time(),
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
        :param hash_val: 工作量证明的哈希值
        :param proof: 工作量证明的随机数
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
        :param block:
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

    def new_transaction(self, s_addr: str, r_addr: str, amount: float, nlock_time=None):

        """
        创建一个新的交易，添加到我创建的下一个区块中
        :param s_addr: 发送者地址，发送数字币的地址
        :param r_addr: 接受者地址，接受数字币的地址
        :param amount: 数字币数量
        :param nlock_time: 交易级别的时间
        :return: 记录本次交易的区块索引
        """

        if nlock_time and nlock_time < time():
            raise ValueError(f"nlock_time 需要大于当前时间")

        money = 0
        if s_addr != '0':
            # 判断发送者是否有足够多的数字货币用于交易
            # todo 后续替换为检测 UTXO
            for block in self.chain:
                for transactions in block['transactions']:
                    if transactions['s_addr'] == s_addr:
                        money -= transactions['amount']
                    if transactions['r_addr'] == s_addr:
                        money += transactions['amount']

            if money < amount:
                raise ValueError(f"余额不足")

        # 交易账本，可包含多个交易

        trans = {
            's_addr': s_addr,
            'r_addr': r_addr,
            'amount': amount,
            "nlock_time": nlock_time or len(self.chain),
        }
        trans["txid"] = self.hash(trans)

        self.current_transactions.append(trans)

    def register_node(self, port):
        """
        添加新的节点进入区块链网络，本地运行只需要端口
        :param port: 新节点的端口
        """
        self.nodes.add(port)

    def valid_chain(self, chain) -> bool:
        """
        检验区块链是否是合法的
        1.检查区块链是否连续
        2.检查工作量证明是否正常
        :param chain: 一份区块链
        """
        i = 1
        while i < len(chain):
            prv_blocks, block = chain[i - 1], chain[i]
            # id 是连续的
            if prv_blocks["index"] != block["previous_hash"] or not self.valid_proof(block["proof"], block):
                return False
            i += 1
        return True

    def resolve_conflicts(self):
        """
        共识算法，确保区块链网络中每个网络节点存储的区块链都是一致的，通过长区块链替换短区块链实现
        :return: True 替换 False不替换
        """
        new_chain = None
        # 本地区块链的长度
        local_len = len(self.chain)

        for node in self.nodes:
            # 访问节点的一个接口，拿到该接口的区块链长度和区块链本身
            try:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']

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


if __name__ == "__main__":
    chain = BlockChain()
    chain.new_transaction("0", "b", 10)
    chain.new_block()
    print(chain)