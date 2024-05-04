from Utils import SingleSign, SingleVerify, MerkleTree, Send_Data, Str_to_Bytes
from aiohttp import web
import asyncio


class Node:
    def __init__(self, number_i):
        self._private_key = b''
        self._total_public_key = b''
        self._merkel_tree = MerkleTree([])
        self._name = 'node_' + str(number_i)
        self._number_i = number_i
        self._register_store_list = []
        self._register_store_dict = {}
        self._challenge_store = {}

        self.Start_Listening()

    def Start_Listening(self):
        app = web.Application()
        if self._number_i == 0:
            app.router.add_post('/SRegister', self.Handle_Register)
            print('Node_'+str(self._number_i)+' :Listening on 127.0.0.1:'+str(8080 + self._number_i))

        web.run_app(app, host='127.0.0.1', port=8080 + self._number_i)


    async def Handle_Register(self, request):
        print('Node_'+str(self._number_i)+': Handling Register')
        data = await request.json()
        # print(data)
        SRegister = Str_to_Bytes(data['SRegister'])
        SRegister_list = []
        while len(SRegister) > 0:
            SRegister_list.append(SRegister[:16+16+1])
            SRegister = SRegister[16+16+1:]
        MT = MerkleTree(self._register_store_list + SRegister_list)

        # Broadcast the proposal for Consensus
        Signed_Pr = SingleSign(self._private_key, SRegister + MT.get_root())
        if self.Broadcast_Pr(Signed_Pr):
            self.Register_Store(SRegister_list)
            print('Consensus Reached, and register has been stored')
            return web.json_response({'Message': 'Your SRegister request have been updated.'})
        else:
            print('Consensus Reached, and register has been stored')
            return web.json_response({'Message': 'Your SRegister request failed, due to consensus failed.'})



    def Register_Store(self, data):
        self._register_store_list += data
        for register in data:
            self._register_store_dict[register[:16]] = register[16:]
        self._merkel_tree = MerkleTree(self._register_store_list)
        print(self._register_store_list)

    def Broadcast_Pr(self, Propose:bytes):
        # todo: the internal function need to be filled
        return True

    def ACom(self, SUPI: bytes, PK_SN: bytes):
        """Propose process function"""
        if not (SUPI in self._register_store_dict and self._register_store_dict[SUPI][-1] == b'1'):
            return False
        H_SUCI = SUPI # TODO:
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
    node = Node(0)
