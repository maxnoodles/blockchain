import hashlib
import binascii
import sys
from collections.abc import Iterable


class MerkleTools(object):
    def __init__(self, hash_type="sha256"):
        hash_type = hash_type.lower()
        if hash_type in ["sha256", "md5"]:
            self.hash_function = getattr(hashlib, hash_type)
        else:
            raise Exception("`hash_type` {} nor supported".format(hash_type))

        self.reset_tree()

    def _to_hex(self, x):
        return x.hex()

    def reset_tree(self):
        self.leaves = list()
        self.levels = None
        self.is_ready = False

    def add_leaf(self, values, do_hash=False):
        self.is_ready = False
        # check if single leaf
        if not isinstance(values, tuple) and not isinstance(values, list):
            values = [values]
        for v in values:
            if do_hash:
                v = v.encode("utf-8")
                v = self.hash_function(v).hexdigest()
            v = bytes.fromhex(v)
            self.leaves.append(v)

    def get_leaf(self, index):
        return self._to_hex(self.leaves[index])

    def get_leaf_count(self):
        return len(self.leaves)

    def get_tree_ready_state(self):
        return self.is_ready

    def _calc(self, l, r):
        return self.hash_function(l + r).digest()

    def _calculate_next_level(self):
        solo_leave = None
        N = len(self.levels[0])  # number of leaves on the level
        if N % 2 == 1:  # if odd number of leaves on the level
            solo_leave = self.levels[0][-1]
            N -= 1

        new_level = []
        for l, r in zip(self.levels[0][0:N:2], self.levels[0][1:N:2]):
            new_level.append(self._calc(l, r))
        if solo_leave is not None:
            new_level.append(solo_leave)
        self.levels = [new_level] + self.levels  # prepend new level

    def make_tree(self):
        self.is_ready = False
        if self.get_leaf_count() > 0:
            self.levels = [self.leaves]
            while len(self.levels[0]) > 1:
                self._calculate_next_level()
        self.is_ready = True

    def get_merkle_root(self):
        if self.is_ready:
            if self.levels is not None:
                return self._to_hex(self.levels[0][0])
            else:
                return None
        else:
            return None

    def get_proof(self, index):
        if self.levels is None:
            return None
        elif not self.is_ready or index > len(self.leaves) - 1 or index < 0:
            return None
        else:
            proof = []
            for x in range(len(self.levels) - 1, 0, -1):
                level_len = len(self.levels[x])
                if (index == level_len - 1) and (
                    level_len % 2 == 1
                ):  # skip if this is an odd end node
                    index = int(index / 2)
                    continue
                is_right_node = index % 2  # 余 1 则为右边位置的索引
                sibling_index = index - 1 if is_right_node else index + 1
                sibling_pos = "left" if is_right_node else "right"
                sibling_value = self._to_hex(self.levels[x][sibling_index])
                proof.append({sibling_pos: sibling_value})
                index = int(index / 2.0)
            return proof

    def validate_proof(self, proof, target_hash, merkle_root):
        merkle_root = bytes.fromhex(merkle_root)
        target_hash = bytes.fromhex(target_hash)
        if len(proof) == 0:
            return target_hash == merkle_root
        else:
            proof_hash = target_hash
            for p in proof:
                # 获取字典单个 key 和 value
                ((k, v),) = p.items()
                sibling = bytes.fromhex(v)
                if k == "left":
                    proof_hash = self.hash_function(sibling + proof_hash).digest()
                else:
                    proof_hash = self.hash_function(proof_hash + sibling).digest()
            return proof_hash == merkle_root


if __name__ == "__main__":
    mt = MerkleTools()
    hex_data = "05ae04314577b2783b4be98211d1b72476c59e9c413cfb2afa2f0c68e0d93911"
    list_data = ["Some text data", "perhaps"]

    mt.add_leaf(hex_data)
    mt.add_leaf(list_data, True)
    leaf_count = mt.get_leaf_count()
    leaf_value = mt.get_leaf(1)
    print(leaf_value)
    mt.make_tree()

    root_value = mt.get_merkle_root()
    print(root_value)

    proof_1 = mt.get_proof(1)
    print(proof_1)

    target_hash = "a7669b9bd589d1d4a1d122c0b2209d15747bfbea01663139b524b26e97afe183"

    print(mt.validate_proof(proof_1, leaf_value, root_value))  # True
