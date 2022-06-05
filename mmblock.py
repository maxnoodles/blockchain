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
            'previous_hash': self.chain[-1]["index"]
        }
        # 从新置空
        self.current_transactions = []
        # 将区块添加到区块链中，此时交易账本是空，工作量证明是空
        self.chain.append(block)
        return block
