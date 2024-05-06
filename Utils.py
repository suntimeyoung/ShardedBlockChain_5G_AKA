import asyncio
import hashlib
from aiohttp import ClientSession, ClientError
import pickle, json
from binascii import hexlify, unhexlify




def Single_Signature_Sign(private_key: bytes, buf: bytes):
    '''Signature Generation Algorithm for MNO'''
    signature = SHA256_Hash(buf)
    return signature


def Single_Signature_Verify(public_key: bytes, buf: bytes, signature: bytes):
    '''Signature Verification Algorithm for MNO'''
    print("Verifying signature: ", signature, " with ", public_key, ", message: ", buf)
    if SHA256_Hash(buf) == signature:
        return True
    return False


def Threshold_Signature_Sign(private_key: bytes, buf: bytes):
    """Generate the threshold signature"""
    signature = SHA256_Hash(buf)
    return signature


def Threshold_Signature_Verify(public_key: bytes, buf: bytes, signature: bytes):
    """Verify the threshold signature"""
    if signature == SHA256_Hash(buf):
        return True
    return False


def Total_Signature_Generate(signature_list: list[bytes], buf: bytes):
    """Aggregate the threshold signature"""
    print("Aggregating the threshold signature")
    return buf

def Total_Signature_Verify(TPK: bytes, buf: bytes, total_signature: bytes):
    print("Verifying the aggregated total signature")
    if SHA256_Hash(buf) == total_signature:
        return True
    return False




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


async def Send_Data(url: str, data: dict):
    print('Sending data to: ' + url)
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


async def Send_Data_Parallel_Same(urls: list[str], data: dict):
    tasks = [Send_Data(url, data) for url in urls]
    response_list = await asyncio.gather(*tasks)
    return response_list


async def Send_Data_Parallel_Each(urls: list[str], data_list: list[dict]):
    tasks = [Send_Data(url, data) for url, data in zip(urls, data_list)]
    response_list = await asyncio.gather(*tasks)
    return response_list


# Simple Utils
def Obj_To_Str(obj: object) -> str:
    return hexlify(pickle.dumps(obj)).decode('ascii')


def Str_To_Obj(s: str) -> object:
    return pickle.loads(unhexlify(s.encode('ascii')))


def Bytes_To_Str(b: bytes) -> str:
    return hexlify(b).decode('ascii')


def Str_to_Bytes(s: str) -> bytes:
    return unhexlify(s.encode('ascii'))


def Obj_To_Bytes(obj: object) -> bytes:
    """将Python对象转换为bytes类型。"""
    return pickle.dumps(obj)


def Bytes_To_Obj(b: bytes) -> object:
    """将bytes类型还原为Python对象。"""
    return pickle.loads(b)


def SHA256_Hash(data: bytes) -> bytes:
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.digest()