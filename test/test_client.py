import aiohttp
import asyncio

async def send_data():
    async with aiohttp.ClientSession() as session:
        url = 'http://127.0.0.1:8080/data'
        data = {'message': 'Hello, Server!'}  # 发送的数据
        async with session.post(url, json=data) as response:
            print(await response.text())  # 打印服务器的响应

if __name__ == '__main__':
    asyncio.run(send_data())
