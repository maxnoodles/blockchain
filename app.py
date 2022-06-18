import json
from uuid import uuid4

from flask import jsonify, request, Flask

from myblockchain import BlockChain
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from utils import generate_ecdsa_keys

app = Flask(__name__)
NODE_ADDRESS_PATH = 'host_address.txt'


@app.route('/mine', methods=['GET'])
def mine():
    '''
    建立新区块
    :return:
    '''
    if not blockchain.chain:
        blockchain.new_transaction([('0', 0)], [(host_address, 50, "P2PK")])
        block = blockchain.new_block()
        response = {
            'message': '创世区块建立',
            'index': block['index'],
            'height': block["height"],
            'transactions': block['transactions'],
            'proof': block['proof'],
            'previous_hash': block['previous_hash'],
        }
        return jsonify(response), 200

    # 挖矿获得一个数字货币奖励，将奖励的交易记录添加到账本中，其他的交易记录通过new_transaction接口添加
    blockchain.new_transaction([('0', 0)], [(host_address, 50, "P2PK")])
    block = blockchain.new_block()

    response = {
        'message': '新区块建立',
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
    }

    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    '''
    将新的交易添加到最新的区块中
    :return:
    '''
    values = request.get_json()

    required = ['txid_in_list', 'out_list']
    if not all(k in values for k in required):
        return '缺失必要字段', 400

    blockchain.new_transaction(values['txid_in_list'], values['out_list'])

    response = {'message': f'交易账本被添加到新的区块中{len(blockchain.chain)}'}
    return jsonify(response), 200


@app.route('/chain', methods=['GET'])
def full_chain():
    '''
    获得完整的区块链
    :return: 整份区块链
    '''
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None:
        return 'Error:提供有效节点列表', 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': '新节点加入区块链网络',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 200


@app.route('/nodes', methods=['GET'])
def nodes():
    response = {
        'nodes': list(blockchain.nodes),
    }
    return jsonify(response), 200


@app.route('/node/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {
            'message': '本节点区块链被替换',
            'new_cha n': blockchain.chain
        }
    else:
        response = {
            'message': '本节点区块链是权威的(区块链网络中最长的)',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


def get_host_address(host):
    p = Path(NODE_ADDRESS_PATH)
    addr_map = {}
    if not p.exists():
        p.touch()
    else:
        with p.open("r") as f:
            addr_map = json.loads(f.read())
    if host not in addr_map:
        addr_map[host] = generate_ecdsa_keys()
        with p.open("w") as f:
            f.write(json.dumps(addr_map))
    return addr_map
        

if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='服务启动时对应的端口')
    args = parser.parse_args()
    port = args.port

    host = f'{"127.0.0.1"}:{port}'
    blockchain = BlockChain(host)
    blockchain.reload_by_file()
    blockchain.init_nodes(host)
    
    host_address_map = get_host_address(host)
    host_address = host_address_map[host][0]

    with ThreadPoolExecutor(max_workers=3,) as executor:
        executor.submit(blockchain.file_sync)
        executor.submit(blockchain.timing_sync)
        executor.submit(app.run, host='localhost', port=port)

