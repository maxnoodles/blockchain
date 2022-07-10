from unittest import TestCase

from utils import (
    generate_ecdsa_keys,
    sign_data,
    validate_sig_data,
    build_simple_vin,
    build_sig,
    build_script_pubkey,
    validate_script,
    hash_256,
    build_multi_script, sign_byte, validate_sig_byte,
)


class UtilTest(TestCase):
    def setUp(self):
        self.pk, self.sk = generate_ecdsa_keys(write_file=False)

    def test_validate_sig_str(self):
        pk = "qSXkT8ZJvXhzmaEJLABgxVvqJUX1wgLjPm2pKJ7kgREMNB5KADn2JXDW33J1C7SuWoPPTgVhvYj8HyKHXDoDXge"
        sk = "3WXGsziAPqHgpjYqxY1HpVMBNGS9Yj3G4SgN7nyb3SkL"
        txid = "521137f91350534065ce21477d4ac169eb3622e5470da5d9b212875e52d0d1d0"
        # sig = '5uinHcwrPusBzLm5p9ah9qsqWfn86FxiPMMCV97tM2mYuKh71ko2V3APTb3q5cn9sm7mEYgMoQB7GTXT45ruEuKN'
        sig = sign_data(sk, txid)
        print(sig)
        ret = validate_sig_data(pk, sig, txid)
        self.assertTrue(ret)

    def test_validate_sig_data(self):
        data = {"a": 1}
        sig = sign_data(self.sk, data)
        ret = validate_sig_data(self.pk, sig, data)
        self.assertTrue(ret)

    def test_validate_script(self):
        txid = "521137f91350534065ce21477d4ac169eb3622e5470da5d9b212875e52d0d1d0"
        vout = 0
        test_data = build_simple_vin(txid, vout)
        test_data["sig"] = build_sig(test_data, [self.sk], self.pk)

        script_type = "P2PKH"
        lock_script = build_script_pubkey(hash_256(self.pk), script_type)

        ret = validate_script(lock_script, script_type, test_data)
        self.assertTrue(ret)

    def test_validate_multi_script(self):
        pk1, sk1 = generate_ecdsa_keys(write_file=False)
        pk2, sk2 = generate_ecdsa_keys(write_file=False)
        pk3, sk3 = generate_ecdsa_keys(write_file=False)

        need_sig_nums = 2
        multi_script, script_hash = build_multi_script([pk1, pk2, pk3], need_sig_nums)

        txid = "521137f91350534065ce21477d4ac169eb3622e5470da5d9b212875e52d0d1d0"
        vout = 0
        test_data = build_simple_vin(txid, vout)
        test_data["redeem_script"] = multi_script
        test_data["sig"] = build_sig(test_data, [sk1, sk2], multi_script)

        script_type = "P2SH"
        lock_script = build_script_pubkey(script_hash, script_type)

        ret = validate_script(lock_script, script_type, test_data)
        self.assertTrue(ret)
