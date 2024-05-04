import asyncio
import secrets
from binascii import hexlify

from Utils import SingleSign, Send_Data


class MNO:
    def __init__(self, shard_count):
        self._private_key = b''
        self._shard_count = shard_count
        self.SRegister = [[] for _ in range(self._shard_count)]


    def Generate_SRegister(self, SUPI: bytes, K: bytes, b: bytes):
        """Generate SUPI register request and grouping these requests by SUPI"""
        self.SRegister[self.Choose_Shard_in_BC(SUPI)].append(SUPI + K + b)

    def Choose_Shard_in_BC(self, SUPI:bytes):
        """Choose the shard in the blockchain to send to"""
        return SUPI[-1] % self._shard_count

    def Send_SRegister_Request(self):
        """Send each SRegister"""
        for i in range(self._shard_count):
            url = 'http://127.0.0.1:' + str(i+8080) + '/SRegister'
            for SR in self.SRegister[i]:
                SR_signed = SingleSign(self._private_key, SR)
                data = {'SRegister': hexlify(SR_signed).decode('ascii') }
                print('MNO: Registering, sending to ' + url)
                response = asyncio.run(Send_Data(url, data))
                print(response['Message'])
            self.SRegister[i].clear()
        return True

    def Random_Gen(self):
        SUPI = secrets.token_bytes(16)
        K = secrets.token_bytes(16)
        b = bytes([1])
        return SUPI, K, b


if __name__ == "__main__":
    mno = MNO(1)
    SUPI, K, b = mno.Random_Gen()
    mno.Generate_SRegister(SUPI, K, b)
    SUPI, K, b = mno.Random_Gen()
    mno.Generate_SRegister(SUPI, K, b)
    mno.Send_SRegister_Request()
