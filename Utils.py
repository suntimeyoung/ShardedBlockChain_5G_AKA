import hashlib
from aiohttp import ClientSession, ClientError
import pickle, json
from binascii import hexlify, unhexlify

def Obj_To_Str(obj):
    return hexlify(pickle.dumps(obj)).decode('ascii')


def Str_To_Obj(str):
    return pickle.loads(unhexlify(str.encode('ascii')))


def Bytes_To_Str(b):
    return hexlify(b).decode('ascii')


def Str_to_Bytes(s):
    return unhexlify(s.encode('ascii'))


def Obj_To_Bytes(obj):
    """将Python对象转换为bytes类型。"""
    return pickle.dumps(obj)


def Bytes_To_Obj(b):
    """将bytes类型还原为Python对象。"""
    return pickle.loads(b)


def SingleSign(key: bytes, buf: bytes):
    '''Signature Generation Algorithm for MNO'''
    return buf


def SingleVerify(key: bytes, buf: bytes):
    '''Signature Verification Algorithm for MNO'''
    return True


class MerkleTree:
    def __init__(self, data):
        self.tree = []
        self._dic = {}
        if len(data) > 0:
            # 初始数据转化为哈希，为叶子节点
            self.leaves = [self._hash(d) for d in data]
            # 构建默克尔树并存储根节点
            self.root = self._build_tree(self.leaves)
            for leaf in data:
                self._dic[leaf[:16]] = leaf[16:]

    def _hash(self, data):
        # 采用 SHA-256 哈希算法
        return hashlib.sha256(data).digest()

    def _build_tree(self, leaves):
        self.tree.append(leaves)
        n = len(leaves)
        if n == 1:
            return leaves[0]
        # 如果节点数不是偶数，复制最后一个哈希节点
        if n % 2 == 1:
            leaves.append(leaves[-1])

        # 创建上一层的节点
        parent_layer = []
        for i in range(0, len(leaves), 2):
            parent_hash = self._hash(leaves[i] + leaves[i + 1])
            parent_layer.append(parent_hash)
        return self._build_tree(parent_layer)

    def get_root(self):
        return self.root


def MTCom(MT_leaves: list[list[bytes]]):
    """Function: computing the Merkel tree and its root"""
    data = [b''.join(tmp) for tmp in MT_leaves]
    MT = MerkleTree(data)
    return MT.tree, MT.root


async def Send_Data(url, data):
    """Send data to certain url and wait for response
        url = 'http://127.0.0.1:8080/data'
        data = {'message': 'Hello, Server!'}
    """
    try:
        async with ClientSession() as session:
            async with session.post(url, json=data) as response:
                # 检查HTTP状态码
                if response.status == 200:
                    return await response.json()
                else:
                    # 可以记录日志或者抛出异常
                    return {'Message': f"HTTP Error: {response.status}"}
    except ClientError as e:
        # 处理连接问题等网络级别的异常
        return {'Message': f"Client error: {str(e)}"}
    except Exception as e:
        # 处理未预见的异常
        return {'Message': f"Unexpected error: {str(e)}"}
