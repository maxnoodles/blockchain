import json
import time
from uuid import uuid4

from flask import jsonify, request, Flask

from myblockchain import BlockChain
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)

# TODO 矿工地址
node_identifier = str(uuid4()).replace('-', '')
# 实例化区块链


@app.route('/mine', methods=['GET'])
def mine():
    '''
    建立新区块
    :return:
    '''
    if not blockchain.chain:
        blockchain.new_transaction([('0', 0)], [(node_identifier, "P2PK", 50)])
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
    blockchain.new_transaction([('0', 0)], [(node_identifier, "P2PK", 50)])
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
        'total_nodes': list(blockchain.host + blockchain.other_nodes),
    }
    return jsonify(response), 200


@app.route('/node/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {
            'message': '本节点区块链被替换',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': '本节点区块链是权威的(区块链网络中最长的)',
            'chain': blockchain.chain
        }
    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='服务启动时对应的端口')
    args = parser.parse_args()
    port = args.port

    host = '127.0.0.1'
    blockchain = BlockChain(host)
    with ThreadPoolExecutor(max_workers=3) as executor:
        executor.submit(blockchain.file_sync)
        executor.submit(blockchain.timing_sync)
        executor.submit(app.run, host='localhost', port=port)

