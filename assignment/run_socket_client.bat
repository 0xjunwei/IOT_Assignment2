cd /d %~dp0

cmd.exe /K "conda activate iot_env & python.exe socket_client.py 127.0.0.1 8889"
