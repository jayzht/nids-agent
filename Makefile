.PHONY: help setup fetch fetch-domain samples real benchmark alerts suricata sigma pdf-docs index run test eval sweep docker clean

PY := .venv/bin/python

help:
	@echo "make setup   创建虚拟环境并安装依赖"
	@echo "make fetch   拉取公开文档语料（GitHub 不通时加 PROXY=...）"
	@echo "make fetch-domain  拉取 NIDS 领域语料（Suricata/Zeek/RFC/arXiv）"
	@echo "make samples 生成样本流量（端口扫描/DNS隧道/beacon/正常流量/注入）"
	@echo "make real    下载真实恶意流量（约 15MB，不入 git）"
	@echo "make benchmark 在真实样本上跑检测基准，写入 docs/"
	@echo "make alerts  把检测结果转成 eve.json 告警（可 --post 推给 API）"
	@echo "make suricata 下载 ET Open 规则 + Suricata 镜像（多 Agent 签名检测用）"
	@echo "make sigma    拉取 Sigma 规则并转成 Markdown（检测工程语料）"
	@echo "make pdf-docs 抓取 NIST / MS-SMB2 / Snort 3 的 PDF 与 HTML 文档"
	@echo "make index   构建/重建全部知识库索引"
	@echo "make run     启动 FastAPI 服务 http://127.0.0.1:8000"
	@echo "make test    跑单元测试"
	@echo "make eval    跑检索评测"
	@echo "make docker  构建并启动容器（docker compose up -d --build）"

setup:
	python3 -m venv .venv && $(PY) -m pip install -U pip && $(PY) -m pip install -r requirements-dev.txt
	@echo "\n下一步: make fetch && make index && make run"

fetch:
	$(PY) scripts/fetch_corpus.py $(if $(PROXY),--proxy $(PROXY),)

samples:
	$(PY) scripts/make_sample_pcaps.py

suricata:
	$(PY) scripts/fetch_suricata_rules.py

sigma:
	$(PY) scripts/fetch_sigma_rules.py

pdf-docs:
	$(PY) scripts/fetch_pdf_docs.py

real:
	$(PY) scripts/fetch_real_pcaps.py

benchmark:
	$(PY) scripts/benchmark_real.py --write-doc

alerts:
	$(PY) scripts/emit_alerts.py --source all

fetch-domain:
	$(PY) scripts/fetch_domain_corpus.py $(if $(PROXY),--proxy $(PROXY),)

index:
	$(PY) scripts/build_index.py

run:
	$(PY) -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

test:
	$(PY) -m pytest -q

eval:
	$(PY) scripts/run_eval.py

sweep:
	$(PY) scripts/sweep.py

docker:
	docker compose up -d --build

clean:
	rm -rf data/index data/.cache .pytest_cache
