cd /d %~dp0

cmd.exe /K "conda activate iot_env & python.exe web_server.py 5000"

rem http://localhost