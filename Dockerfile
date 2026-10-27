FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

# 流量取证依赖 tshark；非交互安装，避免 debconf 卡住
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark \
 && rm -rf /var/lib/apt/lists/*

ARG PIP_INDEX_URL=https://pypi.org/simple
COPY requirements.txt .
RUN pip install -i ${PIP_INDEX_URL} -r requirements.txt

COPY app ./app
COPY scripts ./scripts

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
