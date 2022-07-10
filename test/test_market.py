from itertools import chain
from unittest import TestCase

from market import MerkleTools
from hashlib import sha256


class TestMerkleTools(TestCase):

    def setUp(self):
        self.mt = MerkleTools(hash_type="sha256")

    def tearDown(self):
        self.mt = MerkleTools(hash_type="sha256")

    def test_add_leaf(self):
        self.mt.add_leaf("1", do_hash=True)
        self.mt.add_leaf(["2", "3"], do_hash=True)
        self.assertEqual(self.mt.get_leaf_count(), 3)
        self.assertFalse(self.mt.is_ready)

    def test_get_leaf(self):
        value = 'test'
        self.mt.add_leaf(value, do_hash=True)
        leaf_value = self.mt.get_leaf(0)
        value_hex = sha256(value.encode()).hexdigest()
        self.assertEqual(value_hex, leaf_value)

    def test__calculate_next_level(self):
        self.fail()

    def test_make_tree(self):
        val = ['aa', 'bb', 'cc']
        self.mt.add_leaf(val[0], do_hash=True)
        self.mt.add_leaf(val[1:], do_hash=True)
        leaves = [sha256(v.encode()).digest() for v in val]
        self.assertEqual(leaves, self.mt.leaves)

        self.mt.make_tree()
        self.assertTrue(self.mt.is_ready)

        second_level = [self.mt._calc(leaves[0], leaves[1]), leaves[2]]
        root_level = [self.mt._calc(second_level[0], second_level[1])]
        levels = [root_level, second_level, leaves]
        self.assertEqual(self.mt.levels, levels)
        self.assertEqual(self.mt.get_merkle_root(), root_level[0])

    def test_validate_proof(self):
        val = ['aa', 'bb', 'cc']
        self.mt.add_leaf(val, do_hash=True)
        self.mt.make_tree()
        proof = [{'right': '3b64db95cb55c763391c707108489ae18b4112d783300de38e033b4c98c3deaf'},
                 {'right': '355b1bbfc96725cdce8f4a2708fda310a80e6d13315aec4e5eed2a75fe8032ce'}]

        self.proof = self.mt.get_proof(0)
        proof_0 = self.proof
        self.assertEqual(proof_0, proof)

        leaf_0 = self.mt.get_leaf(0)
        root_val = self.mt.get_merkle_root()
        ret = self.mt.validate_proof(proof_0, leaf_0, root_val)
        self.assertTrue(ret)

