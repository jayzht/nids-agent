.PHONY: help setup fetch index run test eval clean

PY := .venv/bin/python

help:
	@echo "make setup   创建虚拟环境并安装依赖"
	@echo "make fetch   拉取公开文档语料（GitHub 不通时加 PROXY=...）"
	@echo "make index   构建/重建全部知识库索引"
	@echo "make run     启动 FastAPI 服务 http://127.0.0.1:8000"
	@echo "make test    跑单元测试"
	@echo "make eval    跑检索评测"

setup:
	python3 -m venv .venv && $(PY) -m pip install -U pip && $(PY) -m pip install -r requirements.txt
	@echo "\n下一步: make fetch && make index && make run"

fetch:
	$(PY) scripts/fetch_corpus.py $(if $(PROXY),--proxy $(PROXY),)

index:
	$(PY) scripts/build_index.py

run:
	$(PY) -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

test:
	$(PY) -m pytest -q

eval:
	$(PY) scripts/run_eval.py

clean:
	rm -rf data/index data/.cache .pytest_cache
