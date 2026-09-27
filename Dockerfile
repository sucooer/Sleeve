# 纯标准库项目，无需 pip 依赖 —— 直接使用 alpine 最小镜像
FROM python:3.13-alpine

# 关闭 pyc 写入与输出缓冲，省掉一层无用字节
# 容器内必须绑 0.0.0.0，否则宿主机的端口映射进不来。
# 启动守卫判断的是「发布地址」而不是容器内网卡：compose 会传 SLEEVE_PUBLISH_BIND；
# 直接用 docker run 又没有 SLEEVE_AUTH 时，需要显式设 SLEEVE_AUTH_ALLOW_OPEN=1。
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SLEEVE_HOST=0.0.0.0

WORKDIR /app

# 无第三方依赖，无多阶段构建需求；直接把 src/（后端 + 前端脚本与样式）
# 与 public/（纯静态资源）一起复制进来
COPY src/ src/
COPY public/ public/

# 非 root 运行，提升容器安全性
RUN adduser -D -u 10001 appuser \
    && chown -R appuser:appuser /app

# 出网响应缓存的落点。必须在镜像里就把目录和属主一起建好：
# docker 首次初始化一个具名卷时，会沿用镜像里该路径的内容与属主 ——
# 少了这两步，容器内以 appuser 身份写缓存会 Permission denied，
# 而且这个错要到第一次真实查询才暴露，容器看起来是健康的。
RUN mkdir -p /data && chown -R appuser:appuser /data
ENV SLEEVE_CACHE_DIR=/data

USER appuser

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=4).status==200 else 1)" || exit 1

CMD ["python", "src/app.py"]
