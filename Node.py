from Utils import (Single_Signature_Sign, Single_Signature_Verify, MerkleTree,
                   Threshold_Signature_Sign, Threshold_Signature_Verify,
                   Total_Signature_Generate, Total_Signature_Verify,
                   Str_to_Bytes, Bytes_To_Str,
                   Obj_To_Bytes, Bytes_To_Obj,
                   Obj_To_Str, Str_To_Obj,
                   Send_Data_Parallel_Same,
                   SHA256_Hash)
from aiohttp import web
import sys


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
        self._last_pr = {}
        self._blockchain = []

    def Start_Listening(self):
        """Listening from MNO, Other Nodes"""
        app = web.Application()
        if self._is_leader:
            app.router.add_post('/SRegister', self.Handle_Register)
            print(self._name + ' :Listening on 127.0.0.1:' + str(self._port) + '/SRegister')
            app.router.add_post('/AU_request', self.Handle_AU_Request)
            print(self._name + ' :Listening on 127.0.0.1:' + str(self._port) + '/AU_request')
            app.router.add_post('/Res_request', self.Handle_Res_Request)
            print(self._name + ' :Listening on 127.0.0.1:' + str(self._port) + '/Res_request')

        app.router.add_post('/Consensus', self.Handle_Propose)
        print(self._name + ' :Listening on 127.0.0.1:' + str(self._port) + '/Consensus')

        web.run_app(app, host='127.0.0.1', port=self._port)

    async def Handle_Res_Request(self, request):
        """Handling response request from AUSF"""
        print(self._name + ': Handling response request')
        data = await request.json()
        # print(data)
        request = Str_to_Bytes(data['request'])
        Res = request[:16]
        H_SUCI = request[16:]
        if not Single_Signature_Verify(Str_to_Bytes(data['public_key']), request, Str_to_Bytes(data['signature'])):
            return web.json_response({'Message': 'Your Res_Request signature is illegal.'})
        K_seaf, check = self.KCom(Res, H_SUCI)
        if not check:
            return web.json_response({'Message': 'Your Response is illegal.'})
        # Broadcast the proposal for Consensus
        Packaged_Pr = Obj_To_Bytes({'Res_request': request, 'K_seaf': K_seaf})
        reply = await self.Broadcast_Pr(Packaged_Pr, b'Res_request')
        # Checking the proposal for consensus
        if reply['check'] and Total_Signature_Verify(self._total_public_key,
                                                     reply['title'] + reply['propose'],
                                                     reply['signature']):
            print('Consensus Reached, and K_seaf has been generated')
            return web.json_response({'Message': 'Your Res_Request have been updated.',
                                      'propose': Bytes_To_Str(reply['propose']),
                                      'signature': Bytes_To_Str(reply['signature'])})
        else:
            print('Consensus Unreached, and Res_Request has been aborted')
            return web.json_response({'Message': 'Your Res_Request request failed, due to consensus failed.',
                                      'propose': Bytes_To_Str(reply['propose']),
                                      'signature': Bytes_To_Str(reply['signature'])})

    async def Handle_AU_Request(self, request):
        """Handling authentication request from AUSF"""
        print(self._name + ': Handling authentication request')
        data = await request.json()
        # print(data)
        request = Str_to_Bytes(data['request'])
        SUPI = request[:16]
        PK = request[16:]
        if not Single_Signature_Verify(Str_to_Bytes(data['public_key']), request, Str_to_Bytes(data['signature'])):
            return web.json_response({'Message': 'Your AU_request signature is illegal.'})
        AUTN, R, hxRes, check = self.ACom(SUPI, PK)
        if not check:
            return web.json_response({'Message': 'Your AU_request is illegal.'})
        # Broadcast the proposal for Consensus
        Packaged_Pr = Obj_To_Bytes({'AU_request': request, 'AUTN': AUTN, 'R': R, 'hxRes': hxRes})
        reply = await self.Broadcast_Pr(Packaged_Pr, b'AU_request')
        # Checking the proposal for consensus
        if reply['check'] and Total_Signature_Verify(self._total_public_key,
                                                     reply['title'] + reply['propose'],
                                                     reply['signature']):
            H_SUCI = SUPI
            self._challenge_store[H_SUCI] = SUPI
            print('Consensus Reached, and AU_challenge has been stored')
            return web.json_response({'Message': 'Your AU_request have been updated.',
                                      'propose': Bytes_To_Str(reply['propose']),
                                      'signature': Bytes_To_Str(reply['signature'])})
        else:
            print('Consensus Unreached, and AU_request has been aborted')
            return web.json_response({'Message': 'Your AU_request request failed, due to consensus failed.',
                                      'propose': Bytes_To_Str(reply['propose']),
                                      'signature': Bytes_To_Str(reply['signature'])})

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
        Packaged_Pr = Obj_To_Bytes({'SRegister_list': SRegister_list, 'MT_root': MT.get_root()})
        reply = await self.Broadcast_Pr(Packaged_Pr, b'SRegister_Pr')
        # Checking the proposal for consensus
        if reply['check'] and Total_Signature_Verify(self._total_public_key,
                                                     reply['title'] + reply['propose'],
                                                     reply['signature']):
            self.Register_Store(SRegister_list)
            print('Consensus Reached, and register has been stored')
            return web.json_response({'Message': 'Your SRegister request have been updated.',
                                      'propose': Bytes_To_Str(reply['propose']), 'signature': Bytes_To_Str(reply['signature'])})
        else:
            print('Consensus Unreached, and register has been aborted')
            return web.json_response({'Message': 'Your SRegister request failed, due to consensus failed.',
                                      'propose': Bytes_To_Str(reply['propose']), 'signature': Bytes_To_Str(reply['signature'])})

    async def Handle_Propose(self, request):
        print(self._name + ': handling propose')
        data = self.Pre_Verify_Pr(await request.json())
        propose = Bytes_To_Obj(data['propose'])
        response = {}
        if data['check'] != b'Signature verified':
            response['Message'] = self._name + ': your signature is illegal'
        else:
            # Handle the last propose, updating local data
            last_pr = data['last_pr']
            if last_pr and Total_Signature_Verify(self._total_public_key,
                                          last_pr['title'] + last_pr['propose'],
                                          last_pr['vote']):
                # last_pr = {'title': title,'propose': propose, 'vote': total_signature}
                # propose = Packaged_pr
                self.Store_On_Blockchain(last_pr['title'] + last_pr['propose'], last_pr['vote'])
                match last_pr['title']:
                    case b'SRegister_Pr':
                        last_SRegister_list = Bytes_To_Obj(last_pr['propose'])['SRegister_list']
                        self.Register_Store(last_SRegister_list)
                        print('SRegister stored successfully')
                    case b'AU_request':
                        request = Bytes_To_Obj(last_pr['propose'])['AU_request']
                        SUPI = request[:16]
                        self._challenge_store[SUPI] = SUPI
                        print('Authentication stored successfully')
                    case b'Res_request':
                        request = Bytes_To_Obj(last_pr['propose'])['Res_request']
                        print('Response request received successfully')
                    case _:
                        print('Error: unknown title [', last_pr['title'], ']')
            else:
                print('Invalid total signature')
            match data['title']:
                case b'SRegister_Pr':
                    # propose = {'SRegister_list': SRegister_list, 'MT_root': MT.get_root()}
                    SRegister_list = propose['SRegister_list']
                    MT_root = propose['MT_root']
                    SRegister = b''.join(propose['SRegister_list'])
                    MT = MerkleTree(self._register_store_list + SRegister_list)
                    if self.Check_SRegister_Legal(SRegister) and MT.get_root() == MT_root:
                        response['Message'] = 'Propose_Agree'
                        print(self._name + ': SRegister_Pr agrees.')
                    else:
                        response['Message'] = 'Propose_Disagree: Illegal register.'
                        print('Propose_Disagree: Illegal register.')
                case b'AU_request':
                    # propose = {'AU_request': request, 'AUTN': Bytes_To_Str(AUTN), 'R': Bytes_To_Str(R), 'hxRes': Bytes_To_Str(hxRes)}
                    request = propose['AU_request']
                    SUPI = request[:16]
                    PK = request[16:]
                    AUTN, R, hxRes, check = self.ACom(SUPI, PK)
                    if check and AUTN == propose['AUTN'] and R == propose['R'] and hxRes == propose['hxRes']:
                        response['Message'] = 'Propose_Agree'
                        print(self._name + ': AU_request agrees.')
                    else:
                        response['Message'] = 'Propose_Disagree: Illegal AU_request.'
                        print('Propose_Disagree: Illegal AU_request.')
                case b'Res_request':
                    # propose = {'Res_request': request, 'K_seaf': K_seaf}
                    request = propose['Res_request']
                    Res = request[:16]
                    H_SUCI = request[16:]
                    K_seaf, check = self.KCom(Res, H_SUCI)
                    if check and K_seaf == propose['K_seaf']:
                        response['Message'] = 'Propose_Agree'
                        print(self._name + ': Res_request agrees.')
                    else:
                        response['Message'] = 'Propose_Disagree: Illegal Res_request.'
                        print('Propose_Disagree: Illegal Res_request.')
                case _:
                    response['Message'] = 'Error'
                    print(self._name + ': Pr is NOT valid.')
        response['public_key'] = Bytes_To_Str(self._public_key)
        response['signature'] = Bytes_To_Str(Threshold_Signature_Sign(self._private_key, data['title'] + data['propose']))
        # print(data['title'] + data['propose'])
        return web.json_response(response)

    def Register_Store(self, data: list[bytes]):
        """After the consensus has been reached, the context of the consensus should be stored"""
        self._register_store_list += data
        for register in data:
            self._register_store_dict[register[:16]] = register[16:]
        self._merkel_tree = MerkleTree(self._register_store_list)

    async def Broadcast_Pr(self, propose: bytes, title: bytes):
        """The fundamental function for broadcasting every kind of proposal"""
        print('Broadcasting Propose: ', title, propose)
        signature = Threshold_Signature_Sign(self._private_key, title + propose)
        data = {'title': Bytes_To_Str(title),
                'public_key': Bytes_To_Str(self._public_key),
                'propose': Bytes_To_Str(propose),
                'signature': Bytes_To_Str(signature),
                'last_pr': Obj_To_Str(self._last_pr)}
        urls = []
        for i in range(self._node_count):
            if i != self._node_seq:
                url = 'http://127.0.0.1:' + str(8080 + self._max_node_in_shard * self._shard_seq + i) + '/Consensus'
                urls.append(url)
        d_signature_list = [signature]
        if len(urls) > 0:
            response_list = await Send_Data_Parallel_Same(urls, data)
            for response in response_list:
                # print("response:", response)
                if (response['Message'] == 'Propose_Agree'
                        and Threshold_Signature_Verify(Str_to_Bytes(response['public_key']), title + propose,
                                                       Str_to_Bytes(response['signature']))):
                    d_signature_list.append(Str_to_Bytes(response['signature']))
        reply = {'title': title, 'propose': propose}
        if len(d_signature_list) > (2 * self._node_count) // 3:
            total_signature = Total_Signature_Generate(d_signature_list, title + propose)
            print('Consensus agreed')
            reply['check'] = True
            reply['signature'] = total_signature
            self._last_pr = {'title': title, 'propose': propose, 'vote': total_signature}
        else:
            reply['check'] = False
            reply['signature'] = Single_Signature_Sign(self._private_key, propose)
        return reply

    def Pre_Verify_Pr(self, data):
        title = Str_to_Bytes(data['title'])
        public_key = Str_to_Bytes(data['public_key'])
        propose = Str_to_Bytes(data['propose'])
        signature = Str_to_Bytes(data['signature'])
        last_pr = Str_To_Obj(data['last_pr'])

        if not Threshold_Signature_Verify(public_key, title + propose, signature):
            print(self._name + ": signature failed.")
            return {'check': b'Signature failed'}
        return {'title': title, 'propose': propose, 'check': b'Signature verified', 'last_pr': last_pr}

    def Check_Public_Key(self, public_key: bytes):
        return True

    def Check_SRegister_Legal(self, SRegister: bytes):
        """The custom function for checking whether the SRegister is legal"""
        return True

    def ACom(self, SUPI: bytes, PK_SN: bytes):
        """Propose process function"""
        if not (SUPI in self._register_store_dict and self._register_store_dict[SUPI][-1] == ord(b'b')):
            return b'', b'', b'', False
        AUTN = b'AUTH'
        R = b'R'
        hxRes = b'hxRes'
        return AUTN, R, hxRes, True

    def KCom(self, Res: bytes, H_SUCI: bytes):
        """Propose process function"""
        if Res == self._challenge_store[H_SUCI]:
            K_seaf = b'K_seaf'
            return K_seaf, True
        return b'', False

    def Store_On_Blockchain(self, pr: bytes, signature: bytes):
        if len(self._blockchain) == 0:
            last_blockchain = b'The blockchain for storing the event happens on nodes'
        else:
            last_blockchain = self._blockchain[-1]
        last_bc_hash = SHA256_Hash(last_blockchain)
        self._blockchain.append(last_bc_hash + pr + signature)
        print('Storing events on blockchain[', len(self._blockchain), ']')
        return


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
