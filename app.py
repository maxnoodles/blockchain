from flask import jsonify, request, Flask, render_template

from myblockchain import BlockChain
from concurrent.futures import ThreadPoolExecutor

from utils import build_sig, get_pk_sk_map, hash_256, build_simple_vin

app = Flask(__name__)


@app.route("/", methods=["POST", "GET"])
def home():
    if request.method == "POST":
        address = request.form.get("address")

        in_logs, out_logs = blockchain.get_addr_in_out_logs(address)
        return render_template(
            "index.html", out_logs=out_logs, in_logs=in_logs, address=address
        )
    if request.method == "GET":
        return render_template("index.html")


@app.route("/utxo/find", methods=["POST"])
def get_utxo():
    address = request.form.get("address")
    utxo_logs, balance = blockchain.get_utxo_balance_out_logs(address)
    return render_template(
        "index.html", utxo_logs=utxo_logs, utxo_balance=balance, utxo_addr=address
    )


@app.route("/utxo", methods=["GET"])
def get_all_utxo():
    return jsonify(blockchain.UTXO), 200


@app.route("/addr/<address>", methods=["GET"])
def address_info(address):

    pk_sk_map = get_pk_sk_map()
    if address in pk_sk_map:
        pk_hash = address
        pk, sk = pk_sk_map.get(address)
    else:
        pk_hash = hash_256(address)
        pk, sk = pk_sk_map.get(pk_hash)
    balance, utxo_logs = blockchain.get_utxo_balance_out_logs(address)
    in_logs, out_logs = blockchain.get_addr_in_out_logs(address)
    data = {
        "pk_hash": pk_hash,
        "pk": pk,
        "sk": sk,
        "balance": balance,
        "utxo_logs": utxo_logs,
        "out_logs": out_logs,
        "in_logs": in_logs,
    }
    return render_template("addr.html", data=data)


@app.route("/gen_sig", methods=["POST"])
def gen_sig():
    data = request.form
    sk, pk, txid, vout = data["sk"], data["pk"], data["txid"], int(data["vout"])
    script_type = blockchain.UTXO[txid][vout]["script_type"]
    if script_type == "P2PK":
        pk = ""
    to_sig_data = build_simple_vin(txid, vout)
    sig = build_sig(to_sig_data, [sk], pk)
    return render_template("index.html", sig=sig, txid=txid, vout=vout)


@app.route("/mine", methods=["GET"])
def mine():
    """
    建立新区块
    :return:
    """
    # 挖矿获得一个数字货币奖励，将奖励的交易记录添加到账本中，其他的交易记录通过new_transaction接口添加
    block = blockchain.new_block()

    response = {
        "message": "新区块建立",
        "index": block["index"],
        "transactions": block["transactions"],
        "proof": block["proof"],
        "previous_hash": block["previous_hash"],
    }

    return jsonify(response), 200


@app.route("/trans/sync_trans", methods=["POST"])
def sync_one_trans():
    trans = request.get_json()
    blockchain.add_trans_and_utxo(trans)
    resp = {"message": f"添加 {trans['txid']} 成功"}
    return jsonify(resp)


@app.route("/trans/new", methods=["POST"])
def new_transaction():
    """
    将新的交易添加到最新的区块中
    :return:
    """
    values = request.get_json()
    required = ["txid_in_list", "out_list"]
    if not all(k in values for k in required):
        return "缺失必要字段", 400
    blockchain.new_transaction(values["txid_in_list"], values["out_list"])
    response = {"message": f"交易账本被添加到新的区块 {len(blockchain.chain)} 中"}
    return jsonify(response), 200


@app.route("/trans/form", methods=["POST"])
def new_transaction_by_form():
    """
    将新的交易添加到最新的区块中
    :return:
    """
    data = request.form
    txid_in_list = [(data["txid"], int(data["vout"]), data["sig"])]
    out_list = [(data["addr"], float(data["value"]), "P2PKH")]
    blockchain.new_transaction(txid_in_list, out_list)
    response = {"message": f"交易账本被添加到新的区块中{len(blockchain.chain)}"}
    return jsonify(response), 200


@app.route("/chain", methods=["GET"])
def full_chain():
    """
    获得完整的区块链
    :return: 整份区块链
    """
    response = {
        "length": len(blockchain.chain),
        "chain": blockchain.chain,
    }
    return jsonify(response), 200


@app.route("/chain/last", methods=["GET"])
def last_block():
    """
    获得完整的区块链
    :return: 整份区块链
    """
    response = {
        "chain": blockchain.last_block,
    }
    return jsonify(response), 200


@app.route("/nodes/register", methods=["POST"])
def register_nodes():
    values = request.get_json()
    nodes = values.get("nodes")
    if nodes is None:
        return "Error:提供有效节点列表", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        "message": "新节点加入区块链网络",
        "total_nodes": list(blockchain.nodes),
    }
    return jsonify(response), 200


@app.route("/nodes", methods=["GET"])
def nodes():
    response = {
        "nodes": list(blockchain.nodes),
    }
    return jsonify(response), 200


@app.route("/node/resolve", methods=["GET"])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {"message": "本节点区块链被替换", "new_cha n": blockchain.chain}
    else:
        response = {"message": "本节点区块链是权威的(区块链网络中最长的)", "chain": blockchain.chain}
    return jsonify(response), 200


if __name__ == "__main__":
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument("-p", "--port", default=5000, type=int, help="服务启动时对应的端口")
    args = parser.parse_args()
    port = args.port

    host = f'{"127.0.0.1"}:{port}'
    blockchain = BlockChain(host)
    blockchain.reload_by_file()
    blockchain.init_nodes(host)

    with ThreadPoolExecutor(
        max_workers=3,
    ) as executor:
        executor.submit(blockchain.file_sync)
        executor.submit(blockchain.timing_sync)
        executor.submit(app.run, host="localhost", port=port)
