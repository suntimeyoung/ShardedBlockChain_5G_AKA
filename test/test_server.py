from aiohttp import web

async def handle(request):
    # 获取请求中的数据
    data = await request.json()
    print(f"Received data: {data}")  # 打印接收到的数据
    return web.Response(text="Data received successfully")

async def init_app():
    app = web.Application()
    app.router.add_post('/data', handle)  # 添加路由
    return app

if __name__ == '__main__':
    app = init_app()
    web.run_app(app, host='127.0.0.1', port=8080)  # 在8080端口启动服务器
