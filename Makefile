# contorell — 常用指令捷徑
#
# 這只是 scripts/ 底下腳本與既有工具的薄封裝，方便記憶；
# 真正的邏輯都在腳本裡，直接呼叫腳本也完全等價（對齊「簡單順手」）。
#
# 用 `make help` 看全部指令。

.DEFAULT_GOAL := help
.PHONY: help install deploy deploy-prod deploy-native deploy-native-sqlite native-status native-logs smoke test lint security logs down rollback clean

# 若 install.sh 已建好 .venv，優先用它裡面的工具（pytest/ruff…），
# 否則退回 PATH 上的同名工具。這樣 `make test` 不需要先手動 activate。
BIN := $(if $(wildcard .venv/bin/python),.venv/bin/,)

help: ## 顯示這份說明
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## 一鍵安裝：產生 .env 與高熵金鑰、檢查前置條件
	@scripts/install.sh

deploy: ## 部署（開發環境，含模擬 AD DC）
	@scripts/deploy.sh

deploy-prod: ## 部署（正式環境，接真實 AD，執行安全關卡）
	@scripts/deploy.sh --env production --no-samba

deploy-native: ## 原生部署（不用 Docker，systemd 服務；預設 PostgreSQL）
	@sudo scripts/deploy-native.sh

deploy-native-sqlite: ## 原生部署 + 檔案型 SQLite（零額外服務，最簡單）
	@sudo scripts/deploy-native.sh --sqlite

native-status: ## 原生服務狀態
	@scripts/deploy-native.sh --status

native-logs: ## 原生服務即時 log
	@scripts/deploy-native.sh --logs

smoke: ## 對執行中的服務跑煙霧測試
	@scripts/smoke-test.sh

logs: ## 追蹤 app 服務即時 log
	@scripts/deploy.sh --logs

down: ## 停止並移除容器（保留資料卷）
	@scripts/deploy.sh --down

rollback: ## 回滾：停掉目前這批容器
	@scripts/deploy.sh --rollback

test: ## 執行完整測試套件（含覆蓋率）
	@$(BIN)pytest tests/ --cov=app --cov-report=term-missing

lint: ## 程式碼風格與型別檢查
	@$(BIN)ruff check app tests

security: ## 本機資安掃描（SAST + SCA）
	@$(BIN)bandit -r app -c pyproject.toml -ll && $(BIN)pip-audit --desc

clean: ## 清除 Python 暫存與快取
	@find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	@rm -rf .pytest_cache .ruff_cache .mypy_cache .coverage coverage.xml
	@echo "已清除暫存檔"
