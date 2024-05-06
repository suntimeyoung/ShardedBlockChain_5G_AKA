from Utils import (Single_Signature_Sign, Single_Signature_Verify, MerkleTree,
                   Threshold_Signature_Sign, Threshold_Signature_Verify,
                   Total_Signature_Generate, Total_Signature_Verify,
                   Str_to_Bytes, Bytes_To_Str,
                   Obj_To_Bytes, Bytes_To_Obj,
                   Obj_To_Str, Str_To_Obj,
                   Send_Data, Send_Data_Parallel_Same)
from aiohttp import web
import sys
import asyncio


class Node:
    def __init__(self, shard_seq, node_seq, node_count, max_node_in_shard):
        self._shard_seq = shard_seq
        self._node_seq = node_seq
        self._node_count = node_count
        self._max_node_in_shard = max_node_in_shard
        self._name = 'Node_' + str(self._node_seq)
        self._is_leader = self._node_seq == 0
        self._port = 8080 + self._shard_seq * self._max_node_in_shard + self._node_seq
        self._private_key = b'node_private_key'
        self._public_key = b'node_public_key'
        self._total_public_key = b'nodes_total_public_key'
        self._merkel_tree = MerkleTree([])
        self._register_store_list = []
        self._register_store_dict = {}
        self._challenge_store = {}

    def Start_Listening(self):
        """Listening from MNO, Other Nodes"""
        app = web.Application()
        if self._is_leader:
            app.router.add_post('/SRegister', self.Handle_Register)
            print(self._name + ' :Listening on 127.0.0.1:' + str(self._port) + '/SRegister')

        app.router.add_post('/Consensus', self.Handle_Propose)
        print(self._name + ' :Listening on 127.0.0.1:' + str(self._port) + '/Consensus')

        web.run_app(app, host='127.0.0.1', port=self._port)

    async def Handle_Register(self, request):
        """Handling register requests from MNO"""
        print(self._name + ': Handling register')
        data = await request.json()
        # print(data)
        SRegister = Str_to_Bytes(data['SRegister'])
        if not Single_Signature_Verify(Str_to_Bytes(data['public_key']), SRegister, Str_to_Bytes(data['signature'])):
            return web.json_response({'Message': 'Your SRegister signature is illegal.'})
        if not self.Check_SRegister_Legal(SRegister):
            return web.json_response({'Message': 'Your SRegister request is illegal.'})
        SRegister_list = []
        while len(SRegister) > 0:
            SRegister_list.append(SRegister[:16 + 16 + 1])
            SRegister = SRegister[16 + 16 + 1:]
        MT = MerkleTree(self._register_store_list + SRegister_list)  # build Merkel Tree

        # Broadcast the proposal for Consensus
        Packaged_Pr = Obj_To_Bytes([SRegister, MT.get_root()])
        if await self.Broadcast_Pr(Packaged_Pr, b'SRegister_Pr'):  # Checking the proposal for consensus
            self.Register_Store(SRegister_list)
            print('Consensus Reached, and register has been stored')
            return web.json_response({'Message': 'Your SRegister request have been updated.'})
        else:
            print('Consensus Unreached, and register has been aborted')
            return web.json_response({'Message': 'Your SRegister request failed, due to consensus failed.'})


    async def Handle_Propose(self, request):
        print(self._name + ': handling propose')
        data = self.Pre_Verify_Pr(await request.json())
        response = {}
        if data['check'] != b'Signature verified':
            response['Message'] = self._name + ': your signature is illegal'
        else:
            match data['title']:
                case b'SRegister_Pr':
                    response['Message'] = 'Propose_Agree'
                case _:
                    response['Message'] = 'Error'
        response['public_key'] = Bytes_To_Str(self._public_key)
        response['signature'] = Bytes_To_Str(Threshold_Signature_Sign(self._private_key, data['propose']))
        return web.json_response(response)


    def Register_Store(self, data: list[bytes]):
        """After the consensus has been reached, the context of the consensus should be stored"""
        self._register_store_list += data
        for register in data:
            self._register_store_dict[register[:16]] = register[16:]
        self._merkel_tree = MerkleTree(self._register_store_list)
        print(self._register_store_list)

    async def Broadcast_Pr(self, propose: bytes, title: bytes):
        """The fundamental function for broadcasting every kind of proposal"""
        print('Broadcasting Propose: ', title, propose)
        signature = Threshold_Signature_Sign(self._private_key, title + propose)
        data = {'title': Bytes_To_Str(title),
                'public_key': Bytes_To_Str(self._public_key),
                'propose': Bytes_To_Str(propose),
                'signature': Bytes_To_Str(signature)}
        urls = []
        for i in range(self._node_count):
            if i != self._node_seq:
                url = 'http://127.0.0.1:' + str(8080 + self._max_node_in_shard * self._shard_seq + i) + '/Consensus'
                urls.append(url)
        d_signature_list = [signature]
        if len(urls) > 0:
            response_list = await Send_Data_Parallel_Same(urls, data)
            for response in response_list:
                print("response:", response)
                if (response['Message'] == 'Propose_Agree'
                        and Threshold_Signature_Verify(Str_to_Bytes(response['public_key']), propose,
                                                    Str_to_Bytes(response['signature']))):
                    d_signature_list.append(Str_to_Bytes(response['signature']))
        if len(d_signature_list) > (2*self._node_count) // 3:
            total_signature = Total_Signature_Generate(d_signature_list, propose)
            return True
        return False

    def Pre_Verify_Pr(self, data):
        title = Str_to_Bytes(data['title'])
        public_key = Str_to_Bytes(data['public_key'])
        propose = Str_to_Bytes(data['propose'])
        signature = Str_to_Bytes(data['signature'])

        if not Threshold_Signature_Verify(public_key, title + propose, signature):
            print(self._name + ": signature failed.")
            return {'check': b'Signature failed'}
        return {'title': title, 'propose': propose, 'check': b'Signature verified'}


    def Check_Public_Key(self, public_key: bytes):
        return True


    def Check_SRegister_Legal(self, SRegister: bytes):
        """The custom function for checking whether the SRegister is legal"""
        return True


    def ACom(self, SUPI: bytes, PK_SN: bytes):
        """Propose process function"""
        if not (SUPI in self._register_store_dict and self._register_store_dict[SUPI][-1] == b'1'):
            return False
        H_SUCI = SUPI  # TODO:
        self._challenge_store[SUPI] = SUPI
        AUTN = b'AUTH'
        R = b'R'
        hxRes = b'hxRes'
        return AUTN, R, hxRes

    def KCom(self, Res: bytes, H_SUCI: bytes):
        """Propose process function"""
        if Res == self._challenge_store[H_SUCI]:
            K_seaf = b'K_seaf'
            return K_seaf
        return False


if __name__ == '__main__':
    if False:
        node = Node(0, 0, 1, 5)
        node.Start_Listening()
    else:
        # 检查是否提供了足够的参数
        if len(sys.argv) < 5:
            print("Usage: python Node.py <shard_number> <node_number> <max_node_in_shard> <max_node_count>")
            sys.exit(1)

        # 解析参数
        shard_number = int(sys.argv[1])
        node_number = int(sys.argv[2])
        max_node_in_shard = int(sys.argv[3])
        max_node_count = int(sys.argv[4])

        # 创建 Node 实例
        node = Node(shard_number, node_number, max_node_in_shard, max_node_count)
        node.Start_Listening()
