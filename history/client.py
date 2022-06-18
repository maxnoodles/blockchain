from datetime import datetime
from pprint import pprint

import click
import requests

from utils import time_format, sign_data


def send_transaction(from_address, to_address, memo, private_key, port=8080):
    if len(private_key) == 64:
        data = {
            "from": from_address,
            "to": to_address,
            "memo": memo,
        }
        _time = time_format(datetime.now())
        signature = sign_data(private_key, data, _time)
        url = f"http://localhost:{port}/post"
        d = {
            "data": data,
            "signature": signature,
            "time": _time
        }
        r = requests.post(url, json=d)
        return r.json()
    else:
        return "Wrong address or key length! Verify and try again."


@click.command()
@click.option('-port', help='port')
@click.option('-fa', help='from address')
@click.option('-ta', help='to address')
@click.option('-memo', help='memo')
@click.option('-pk', help='private_key')
def client(port, fa, ta, memo, pk):
    if all([fa, ta, memo, pk]):
        print(send_transaction(fa, ta, memo, pk, port))


if __name__ == '__main__':
    # client()

    address = "ewEf9xFJV1Bt6/7+gjkfebvlmcuY6wuhXsHqKPGyuCgqguxFjzEV+ayQiwTkPy8gtVuEJRg+nfmRN853RLTFXg=="
    sk = "8c3e50b78fb48eb7761b95561f4ecdd66aa04e180286df93d1507dd63a46a45d"
    to_address = "TnK1vobvj8MRmyN2Y6ZgARj5HCtpMKg+YvjN2c8X39mplufWciP5TxNhOUaCLZT7NNGXnArjg6ZTrgwdprj7qg=="
    pprint(send_transaction(address, to_address, "222", sk))
