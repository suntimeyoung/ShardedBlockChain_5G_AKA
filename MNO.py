import asyncio
import secrets
from binascii import hexlify

from Utils import Single_Signature_Sign, Send_Data_Parallel_Each, Bytes_To_Str, Send_Data


class MNO:
    def __init__(self, shard_count, max_node_in_shard):
        self._private_key = b'MNO_private_key'
        self._public_key = b'MNO_public_key'
        self._shard_count = shard_count
        self._max_node_in_shard = max_node_in_shard
        self._SRegister = [[] for _ in range(self._shard_count)]
        self._SUPI = []


    def Generate_SRegister(self, SUPI: bytes, K: bytes, b: bytes):
        """Generate SUPI register request and grouping these requests by SUPI"""
        self._SRegister[self.Choose_Shard_in_BC(SUPI)].append(SUPI + K + b)

    def Choose_Shard_in_BC(self, SUPI:bytes):
        """Choose the shard in the blockchain to send to"""
        return SUPI[-1] % self._shard_count

    async def Send_SRegister_Request(self):
        """Send each SRegister"""
        urls = []
        data_list = []
        for i in range(self._shard_count):
            # Computing the URL where the SRegister is sent to
            url = 'http://127.0.0.1:' + str(i*self._max_node_in_shard+8080) + '/SRegister'
            SRegister = b''.join(self._SRegister[i])
            signature = Single_Signature_Sign(self._private_key, SRegister)
            if SRegister != b'':
                urls.append(url)
                data_list.append({'SRegister': Bytes_To_Str(SRegister),
                                  'public_key': Bytes_To_Str(self._public_key),
                                  'signature': Bytes_To_Str(signature)})
        print(urls)
        print(data_list)
        response_list = await Send_Data_Parallel_Each(urls, data_list)
        for response in response_list:
            print(response['Message'])
        return True

    def Random_Gen(self):
        SUPI = secrets.token_bytes(16)
        K = secrets.token_bytes(16)
        b = bytes([1])
        return SUPI, K, b

    def Random_Gen_Identified(self):
        SUPI = b'SUPI:' + secrets.token_bytes(16 - 5)
        K = b'K:' + secrets.token_bytes(16 - 2)
        b = b'b'
        return SUPI, K, b

class AUSF:
    def __init__(self, max_node_in_shard):
        self._Res_dic = {}
        self._max_node_in_shard = max_node_in_shard
        self._public_key = b'AUSF_public_key'
        self._private_key = b'AUSF_private_key'
        self._name = 'AUSF'

    async def Send_Authenticate_Request(self, SUPI: bytes, PK: bytes, mno: MNO):
        url = 'http://127.0.0.1:' + str(mno.Choose_Shard_in_BC(SUPI) * self._max_node_in_shard + 8080) + '/AU_request'
        signature = Single_Signature_Sign(self._private_key, SUPI + PK)
        data = {'request': Bytes_To_Str(SUPI + PK),
                'public_key': Bytes_To_Str(self._public_key),
                'signature': Bytes_To_Str(signature)}
        print(url)
        print(self._name, ': sending authenticate request to ', url)
        response = await Send_Data(url, data)
        print(response['Message'])
        return True

    async def Send_Response_Request(self, Res: bytes, H_SUCI: bytes, SUPI: bytes, mno: MNO):
        url = 'http://127.0.0.1:' + str(mno.Choose_Shard_in_BC(SUPI) * self._max_node_in_shard + 8080) + '/Res_request'
        signature = Single_Signature_Sign(self._private_key, Res + H_SUCI)
        data = {'request': Bytes_To_Str(Res + H_SUCI),
                'public_key': Bytes_To_Str(self._public_key),
                'signature': Bytes_To_Str(signature)}
        print(url)
        print(self._name, ': sending authenticate request to ', url)
        response = await Send_Data(url, data)
        print(response['Message'])
        return True



if __name__ == "__main__":
    SUPI_list = []
    shard_count = 1
    max_node_in_shard = 5

    mno = MNO(shard_count, max_node_in_shard)
    for i in range(4):
        SUPI, K, b = mno.Random_Gen_Identified()
        mno.Generate_SRegister(SUPI, K, b)
        SUPI_list.append(SUPI)

    asyncio.run(mno.Send_SRegister_Request())

    # for i in range(2):
    #     SUPI, K, b = mno.Random_Gen_Identified()
    #     mno.Generate_SRegister(SUPI, K, b)
    #     SUPI_list.append(SUPI)
    #
    # asyncio.run(mno.Send_SRegister_Request())

    ausf = AUSF(max_node_in_shard)
    for SUPI in SUPI_list[:3]:
        asyncio.run(ausf.Send_Authenticate_Request(SUPI, b'sn_public_key', mno))

    for SUPI in SUPI_list[:3]:
        asyncio.run(ausf.Send_Response_Request(SUPI, SUPI, SUPI, mno))


