import hashlib
import json
from time import time


def hash_block(block):
    block_str = json.dumps(block, sort_key=True).encode()
    return hashlib.sha256(block_str).hexdigest()


class BlackChain:
    def __init__(self):
        self.current_transactions = None
        self.chain = []
        self.node = set()

    def new_block(self, proof, hash_val):
        """
        创建一个新区块加入到区块链中
        :param hash_val: 工作量证明的哈希值
        :param proof: 工作量证明的随机数
        :return: 一个新区块
        """
        block = {
            "index": hash_val,
            # 高度
            "height": len(self.chain),
            # 时间戳
            "timestamp": time(),
            # 交易账本
            "transaction": self.current_transactions,
            # 工作量证明
            'proof': proof,
            # 上一区块的 hash
            'previous_hash': self.last_block["index"]
        }
        # 从新置空
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

    def proof_of_work(self, last_block):
        '''
        简单的工作量证明算法
        找到一个数，使得区块的hash前4位为0
        :param last_block 上一个区块
        :return: 特殊的数
        '''

        # 工作量证明--->穷举法计算出特殊的数
        last_hash = self.hash(last_block)
        proof = 0
        while self.valid_proof(proof, last_hash) is False:
            proof += 1

        return proof