# blockchain

## Requirements
Python 3.10+

如果将代码中 match-case 替换成 if-else 则 Python 3.6+ 即可


## introduction

详细文档[点击](https://github.com/maxnoodles/blockchain/blob/master/Python%20%E5%AE%9E%E7%8E%B0%E7%AE%80%E5%8D%95%E6%AF%94%E7%89%B9%E5%B8%81.md)查看 

**myblockchain.py** 区块链的主要的代码文件

**app.py** 为区块链提供 web 服务

**utils.py** 提供生成公私钥，写入读取文件等函数

**market.py** 默克尔树的实现代码，参考 https://github.com/Tierion/pymerkletools

**test** 目录包含了重要函数的单元测试