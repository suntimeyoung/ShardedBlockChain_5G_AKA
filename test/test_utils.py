import asyncio

async def main():
    print("Hello")
    await asyncio.sleep(10)  # 异步等待1秒
    print("world")

asyncio.run(main())  # 运行异步主函数
