import time
from argparse import ArgumentParser
from hashlib import sha256
from datetime import datetime

import requests
from flask import Flask, jsonify, render_template, request

from utils import time_format, validate_signature

blockchain = []
PORT = 8080
node_ports = []


# 返回自身区块链高度
def get_height():
    last_block = blockchain[len(blockchain) - 1]
    return last_block["index"]


def hash(data, previous_hash, index, _time):
    return sha256(f"{data}{previous_hash}{index}{_time}".encode("utf8")).hexdigest()


# 新建一个区块
# consignor:寄件人
# consignee：收件人
# memo:备注信息
def make_a_block(data, previous_hash, index):
    time.sleep(0.01)
    _time = time_format(datetime.now())
    return {
        "data": data,
        "previous_hash": previous_hash,
        "hash": hash(data, previous_hash, index, _time),
        "index": index,
        "time": _time
    }


def add_a_block(data):
    last_block = blockchain[-1]
    previous_hash = last_block["hash"]
    index = last_block["index"] + 1
    blockchain.append(make_a_block(data, previous_hash, index))


def make_a_genesis_block():
    data = "this is the genesis block"
    previous_hash = 0
    index = 0
    blockchain.append(make_a_block(data, previous_hash, index))


def validate(blocks):
    i = 1
    while i < len(blocks):
        prv_blocks, block = blocks[i - 1], blocks[i]
        prv_index, prv_hash = prv_blocks["index"], prv_blocks["hash"]
        # id 是连续的
        if prv_index + 1 != block["index"] and prv_hash != block["previous_hash"]:
            return False
        i += 1
    return True


app = Flask(__name__)


@app.route('/', methods=['POST', 'GET'])
def home():
    if request.method == 'POST':
        address = request.form.get('address')

        out_logs = []
        in_logs = []

        for i in range(1, len(blockchain)):
            block = blockchain[i]
            data = block["data"]
            if address == data["from"]:
                out_logs.append(block)
            if address == data["to"]:
                in_logs.append(block)
        return render_template('index.html', out_logs=out_logs, in_logs=in_logs)
    if request.method == 'GET':
        return render_template('index.html')


@app.route('/post', methods=['POST'])
def add_block():
    d = request.get_json()
    data = d.get('data')
    signature = d.get('signature')
    _time = d.get('time')
    if validate_signature(signature, data, _time):
        add_a_block(data)
        return jsonify(blockchain)


@app.route('/say/<string:msg>', methods=['GET'])
def add_block_bak(msg):
    add_a_block(msg)
    return jsonify(blockchain)


@app.route('/blocks/last', methods=['GET'])
def get_last_block():
    last_block = blockchain[len(blockchain) - 1]
    return jsonify(last_block)


@app.route('/blocks/<int:index>', methods=['GET'])
def get_block(index):
    if len(blockchain) >= index:
        block = blockchain[index]
        return jsonify(block)
    else:
        return jsonify({"error": "noindex"})


@app.route('/blocks/<int:from_index>/<int:to_index>', methods=['GET'])
def get_block_from_to(from_index, to_index):
    blocks = []
    l = len(blockchain)
    if to_index >= from_index and l > to_index:
        for i in range(from_index, to_index + 1):
            block = blockchain[i]
            blocks.append(block)
        return jsonify(blocks)
    else:
        return jsonify({"error": "noindex"})


@app.route('/blocks/all', methods=['GET'])
def get_all_block():
    return jsonify(blockchain)


# 查看区块链高度
@app.route('/blocks/height', methods=['GET'])
def get_block_height():
    return jsonify(get_height())


# 查看节点
@app.route('/nodes', methods=['GET'])
def get_get_nodes():
    return jsonify(node_ports)


# 添加节点
@app.route('/nodes/add/<int:port>', methods=['GET'])
def add_nodes(port):
    # 确保不重复添加
    if port not in node_ports:
        node_ports.append(port)
    return jsonify(node_ports)


# 同步区块
@app.route('/blocks/sync', methods=['GET'])
def blocks_sync():
    global blockchain
    for port in node_ports:

        if port == PORT:
            continue

        url = f"http://127.0.0.1:{port}"
        url_height = f'{url}/blocks/height'
        url_all = f'{url}/blocks/all'

        # 尝试同步
        try:
            r_height = int(requests.get(url_height).json())
            height = get_height()

            if r_height > height:
                r_all_block = requests.get(url_all).json()
                if validate(r_all_block):
                    blockchain = r_all_block
                return jsonify("synced")
            else:
                # 不同步
                return jsonify("no synced")

        except Exception:
            return jsonify("error")
    return jsonify("no nodes")


if __name__ == '__main__':
    make_a_genesis_block()

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=8080, type=int, help='port to listen on')
    args = parser.parse_args()
    PORT = args.port
    node_ports.append(PORT)
    app.run(port=PORT)
