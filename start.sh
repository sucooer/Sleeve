#!/bin/sh
# Sleeve 启动脚本（非 Docker 部署用，如宝塔面板 / systemd / 直接 python）。
#
#   用法：./start.sh
#
# 作用：把 .env 里的凭据（SOUNDCHARTS_*、SONOVAULT_API_KEY 等）加载进本进程
# 环境后再启动服务——不用每次手动拼一长串 export / 环境变量前缀。
# 注意 .env 只在本机，已被 .gitignore 排除，绝不入库。
#
# 依赖：src/app.py 同目录存在 .env（参照 .env.example 填写）

cd "$(dirname "$0")" || exit 1

if [ ! -f .env ]; then
    echo "缺少 .env：先 cp .env.example .env 并按需填写。" >&2
    exit 1
fi

# set -a 让 .env 里每个 KEY=VALUE 都自动 export；. 在当前 shell 内执行（不 fork）
set -a
. ./.env
set +a

exec python3 src/app.py "$@"
