@echo off
setlocal enabledelayedexpansion

set shard_number=1
set max_node_in_shard=4

set /a end_shard_number=%shard_number% - 1
set /a end_max_node_in_shard=%max_node_in_shard% - 1

for /L %%i in (0,1,%end_shard_number%) do (
    for /L %%j in (0,1,%end_max_node_in_shard%) do (
        echo "shard_seq = %%i, node_seq = %%j"
        start "" python Node.py %%i %%j %max_node_in_shard% %max_node_in_shard%
    )
)

timeout /t 5 /nobreak
start "" python MNO.py

endlocal
