from Utils import MNOSign
from aiohttp import web, ClientSession, ClientError
import asyncio
import secrets
from binascii import hexlify

class MNO:
    def __init__(self, shard_count):
        self._private_key = b''
        self._shard_count = shard_count
        self.SRegister = [[] for _ in range(self._shard_count)]

    async def Send_Data(self, url, data):
        """Send data to certain url and wait for response
            url = 'http://127.0.0.1:8080/data'
            data = {'message': 'Hello, Server!'}
        """
        try:
            async with ClientSession() as session:
                async with session.post(url, json=data) as response:
                    # 检查HTTP状态码
                    if response.status == 200:
                        return await response.text()
                    else:
                        # 可以记录日志或者抛出异常
                        return f"HTTP Error: {response.status}"
        except ClientError as e:
            # 处理连接问题等网络级别的异常
            return f"Client error: {str(e)}"
        except Exception as e:
            # 处理未预见的异常
            return f"Unexpected error: {str(e)}"

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
                SR_signed = MNOSign(self._private_key, SR)
                data = {'SRegister': hexlify(SR_signed).decode('ascii') }
                print('MNO: Registering, sending to ' + url)
                response = asyncio.run(self.Send_Data(url, data))
                print(response)
            self.SRegister[i].clear()
        return True

    def Random_Gen(self):
        SUPI = secrets.token_bytes(16)
        K = secrets.token_bytes(16)
        b = bytes([1])
        return SUPI, K, b


if __name__ == "__main__":
    mno = MNO(9)
    SUPI, K, b = mno.Random_Gen()
    mno.Generate_SRegister(SUPI, K, b)
    SUPI, K, b = mno.Random_Gen()
    mno.Generate_SRegister(SUPI, K, b)
    mno.Send_SRegister_Request()
