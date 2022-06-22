import copy
import json
import logging
from collections import defaultdict
from pprint import pformat
import time
from pathlib import Path

import requests

from market import MerkleTools
from utils import (
    validate_script,
    check_address_in_script,
    get_host_address,
    build_script_pubkey,
    hash_256,
)

COIN_AWARD = 50


class BlockChain:
    def __init__(self, host: str = None):
        self.current_transactions = []
        self.chain = []
        self.market_trees = []
        self.nodes = {host} if host else set()
        self.UTXO = defaultdict(dict)
        self.full_node = "127.0.0.1:5000"
        self.host = host
        self.file_name = (
            f"./chain_file/{self.host.replace(':', '_')}_chain.txt" if host else ""
        )
        self.address = get_host_address(host)

    def init_block(self):
        return {
            # 高度
            "height": len(self.chain),
            # 时间戳
            "timestamp": time.time(),
            # 上一区块的 hash
            "previous_hash": self.last_block["index"] if self.chain else None,
            # 默克尔树根
            "market_root": self.market(self.current_transactions),
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
        # 矿工奖励
        self.new_transaction(*self.build_mine_in_out())
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

    def build_mine_in_out(self, value=COIN_AWARD):
        return [("0", 0)], [(self.address, value, "P2PKH")]

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
        # sort_keys()：json解析后获得的字典将通过key排序
        block_string = json.dumps(block, sort_keys=True)
        return hash_256(block_string)

    @staticmethod
    def valid_proof(proof, block_hash) -> (bool, str):
        """
        验证工作量证明，计算出的hash是否正确
        对上一个区块的proof和hash与当期区块的proof最sha256运算、
        :param proof: 当前区块的随机数（工作量）
        :param block_hash: 本区块的 hash
        """
        guess = f"{proof}{block_hash}"
        guess_hash = hash_256(guess, b58=False)
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
            "vout": int(vout),
        }
        if sig:
            _in["sig"] = sig
        if redeem_script:
            _in["redeem_script"] = redeem_script
        return _in

    def build_one_vout(self, addr, value, script_type):
        """
        构建一个交易输出
        :param addr: 哈希地址
        :param value: 数量
        :param script_type: 脚本类型
        :return:
        """
        assert script_type in ["P2PK", "P2PKH", "P2SH"]
        out = {
            "script_type": script_type,
            "value": value,
            "script_pubkey": build_script_pubkey(addr, script_type),
        }
        return out

    def new_transaction(
        self,
        txid_in_list: list[tuple[str, int, ...]],
        out_list: list[tuple[str, float, str]],
        nlock_time=None,
    ):

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
        self.is_valid_nlock_time(nlock_time)

        self.is_valid_trans(vin_list)

        # 矿工手续费
        fee = self.get_mine_fee(vin_list, vout_list)
        if fee > 0:
            _, _out = self.build_mine_in_out(value=fee)
            vout_list.append(self.build_one_vout(*_out[0]))

        trans = {
            "vin": vin_list,
            "vout": vout_list,
            "nlock_time": nlock_time or len(self.chain),
        }

        txid = self.hash(trans)
        trans["txid"] = txid

        if txid in self.UTXO:
            raise ValueError("此交易已经被保存在区块中")

        self.add_trans_and_utxo(trans)
        # 广播到其他节点
        self.flood_trans(trans)
        return trans

    def is_valid_nlock_time(self, nlock_time):
        if nlock_time:
            if nlock_time < 500000000:
                if self.height < nlock_time:
                    raise ValueError(f"nlock_time 再指定的区块高度之前无效")
            else:
                if nlock_time < time.time():
                    raise ValueError(f"nlock_time 需要大于当前时间")

    @staticmethod
    def is_mine_trans(vin_list):
        return len(vin_list) == 1 and vin_list[0]["txid"] == "0"

    def get_mine_fee(self, vin_list, vout_list):
        if self.is_mine_trans(vin_list):
            return 0
        else:
            in_value_sum = 0
            for vin in vin_list:
                txid, out_idx = vin["txid"], vin["vout"]
                out_data = self.UTXO[txid][out_idx]
                in_value_sum += out_data["value"]
        out_value_sum = sum([i["value"] for i in vout_list])
        fee = in_value_sum - out_value_sum
        if fee < 0:
            raise ValueError("输入费用小于输出费用")
        return fee

    def is_valid_trans(self, vin_list):
        if self.is_mine_trans(vin_list):
            # 创币交易，跳过
            return True
        else:
            for vin in vin_list:
                txid, out_idx = vin["txid"], vin["vout"]
                if txid == "0":
                    continue
                if txid not in self.UTXO:
                    raise ValueError(f"txid {txid} 无效")
                if out_idx not in self.UTXO[txid]:
                    raise ValueError(f"txid {txid} 使用的 vout {out_idx} 无效")

                # 验证解锁脚本
                out_data = self.UTXO[txid][out_idx]
                if not validate_script(
                    out_data["script_pubkey"],
                    out_data["script_type"],
                    vin,
                    vin.get("redeem_script"),
                ):
                    raise ValueError("script result False")

    def add_trans_and_utxo(self, trans):
        self.current_transactions.append(trans)
        self.adjust_UTXO(trans)

    def flood_trans(self, trans):
        for node in self.nodes:
            if node == self.host:
                continue
            try:
                requests.post(f"http://{node}/trans/sync_trans", json=trans, timeout=5)
            except:
                pass

    def adjust_UTXO(self, trans):
        """
        调整 UTXO
        :param trans: 一个交易
        """
        txid = trans["txid"]
        # UTXO 中删除 vin
        for vin in trans["vin"]:
            in_txid, out = vin["txid"], vin["vout"]
            if in_txid != "0":
                self.UTXO[in_txid].pop(out)
        # UTXO 中增加 vout
        for idx, vout in enumerate(trans["vout"]):
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
            if prv_blocks["index"] != block["previous_hash"] or not self.valid_proof(
                block["proof"], block
            ):
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
                response = requests.get(f"http://{node}/chain")
                if response.status_code == 200:
                    resp_dict = response.json()
                    length = resp_dict["length"]
                    chain = resp_dict["chain"]

                    # 判断邻居节点发送过来的区块链长度是否最长且是否合法
                    if length > local_len and self.valid_chain(chain):
                        print(f"使用长度更长 {length} 的区块链 {chain}")
                        # 使用邻居节点的区块链
                        local_len = length
                        new_chain = chain
            except:
                print(f"节点 {node} 没有开机")
                self.nodes.remove(node)
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
            print(f"开始同步其他节点区块链 {self.nodes}")
            self.resolve_conflicts()

    def file_sync(self):
        """
        定时同步
        :return:
        """
        while True:
            time.sleep(30)
            if self.current_transactions:
                self.new_block()
            self.write_to_file()

    def write_to_file(self):
        print("开始写入节点")
        _dir = "./chain_file"
        path = Path(_dir)
        if not path.exists():
            path.mkdir()
        with open(self.file_name, "w") as f:
            for block in self.chain:
                txt = json.dumps(block, sort_keys=True)
                f.write(f"{txt}\n")

    def reload_by_file(self):
        if Path(self.file_name).exists():
            with open(self.file_name, "r") as f:
                for row in f.readlines():
                    block = json.loads(row)
                    self.chain.append(block)

                    for trans in block["transactions"]:
                        self.adjust_UTXO(trans)

            print(self.UTXO)
            print("从文件加载完成", self.chain)

    def init_nodes(self, host):
        if host == self.full_node:
            return
        try:
            data = {"nodes": list(self.nodes)}
            response = requests.post(
                f"http://{self.full_node}/nodes/register", json=data, timeout=5
            )
            if response.status_code == 200:
                resp_dict = response.json()
                total_nodes = resp_dict["total_nodes"]
                self.nodes.update(total_nodes)
        except Exception as e:
            logging.exception(e)
            # 节点没开机

    def get_addr_in_out_logs(self, address):
        in_logs, out_logs = [], []
        txid_out_set = dict()
        for block in self.chain:
            for trans in block["transactions"]:
                txid = trans["txid"]
                for _in in trans["vin"]:
                    key = (_in["txid"], _in["vout"])
                    if key in txid_out_set:
                        in_logs.append(trans)
                        txid_out_set.pop(key)

                for idx, out in enumerate(trans["vout"]):
                    if check_address_in_script(address, out["script_pubkey"]):
                        out_logs.append(trans)
                        txid_out_set[(txid, idx)] = out["value"]
        return in_logs, out_logs

    def get_utxo_balance_out_logs(self, address):
        utxo_logs = []
        balance = 0
        for txid, out_dict in self.UTXO.items():
            for out_idx, out in out_dict.items():
                if check_address_in_script(address, out["script_pubkey"]):
                    utxo_logs.append({txid: out_dict})
                    balance += out["value"]
        return balance, utxo_logs


if __name__ == "__main__":
    host = "127.0.0.1:5000"
    chain = BlockChain(host)
    chain.reload_by_file()
    for i in range(2):
        chain.new_block()
    chain.write_to_file()
    print(chain)
