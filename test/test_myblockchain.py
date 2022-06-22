from pprint import pprint
from unittest import TestCase

from myblockchain import BlockChain
from utils import hash_256


class TestBlockChain(TestCase):
    def setUp(self):
        self.chain = BlockChain()
        self.mine_trans = {
            "nlock_time": 0,
            "vin": [{"txid": "0", "vout": 0}],
            "vout": [
                {
                    "script_pubkey": f"OP_DUP OP_HASH {self.chain.address} OP_EQUALVERIFY OP_CHECKSIG",
                    "script_type": "P2PKH",
                    "value": 50,
                }
            ],
        }
        self.mine_trans["txid"] = self.chain.hash(self.mine_trans)

    def test_new_block(self):
        block = self.chain.new_block()
        proof = block.pop("proof")

        trans_list = [self.mine_trans]
        expect = {'height': 0,
                  'market_root': self.chain.market(trans_list),
                  'previous_hash': None,
                  "timestamp": block["timestamp"],
                  }
        expect_hash = self.chain.hash(expect)
        expect["index"] = hash_256(f'{proof}{expect_hash}', b58=False)
        expect["transactions"] = trans_list

        self.assertEqual(block, expect)

    def test_new_transaction(self):
        txid_in_list, out_list = self.chain.build_mine_in_out()

        trans = self.chain.new_transaction(txid_in_list, out_list)
        self.assertEqual(trans, self.mine_trans)
