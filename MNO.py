import asyncio
import secrets
from binascii import hexlify

from Utils import Single_Signature_Sign, Send_Data_Parallel_Each, Bytes_To_Str


class MNO:
    def __init__(self, shard_count, max_node_in_shard):
        self._private_key = b'MNO_private_key'
        self._public_key = b'MNO_public_key'
        self._shard_count = shard_count
        self._max_node_in_shard = max_node_in_shard
        self.SRegister = [[] for _ in range(self._shard_count)]


    def Generate_SRegister(self, SUPI: bytes, K: bytes, b: bytes):
        """Generate SUPI register request and grouping these requests by SUPI"""
        self.SRegister[self.Choose_Shard_in_BC(SUPI)].append(SUPI + K + b)

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
            SRegister = b''.join(self.SRegister[i])
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


if __name__ == "__main__":
    mno = MNO(1, 5)
    SUPI, K, b = mno.Random_Gen_Identified()
    mno.Generate_SRegister(SUPI, K, b)
    SUPI, K, b = mno.Random_Gen_Identified()
    mno.Generate_SRegister(SUPI, K, b)
    asyncio.run(mno.Send_SRegister_Request())
