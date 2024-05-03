import hashlib


def MNOSign(key: bytes, buf: bytes):
    '''Signature Generation Algorithm for MNO'''
    return buf


def MNOVerify(key: bytes, buf: bytes):
    '''Signature Verification Algorithm for MNO'''
    return True


class MerkleTree:
    def __init__(self, data):
        # 初始数据转化为哈希，为叶子节点
        self.leaves = [self._hash(d) for d in data]
        self.tree = []
        # 构建默克尔树并存储根节点
        self.root = self._build_tree(self.leaves)

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

    def get_root_hash(self):
        return self.root


def MTCom(MT_leaves: list[list[bytes]]):
    """Function: computing the Merkel tree and its root"""
    data = [b''.join(tmp) for tmp in MT_leaves]
    MT = MerkleTree(data)
    return MT.tree, MT.root
