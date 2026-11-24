-include .env
export

# Docker image, terraform and release targets live in platform.mk. Teams never need them.
-include platform.mk

install:
	cd frontend && npm install
	uv sync --extra fastapi --extra gateway --extra synth
	docker compose build 

.PHONY: synth deploy_up deploy_down deploy_check
synth:  ## Regenerate mcp_server/data/synthetic (pupil census, deprivation, schools, display names) from mcp_server/synth/synth.yaml
	uv run python -m mcp_server.synth

hack: install  ## One command start: keys, one-school mandate, eval pack, containers, first signed call
	cp -n .env.example .env || true
	test -f gateway/state/trusted_list.json || uv run python -m gateway.cli init
	uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o gateway/state/mandate.jwt
	uv run python -m gateway.eval build -o eval_pack
	uv run python -m gateway.cli grant-key
	docker compose up -d --wait
	uv run python -m gateway.cli call --mandate gateway/state/mandate.jwt --agent-key gateway/state/agent.pem \
		--tool search --args '{"query": "P0004", "urn": "SCH01"}'

run:
	uv run python -m gateway.cli grant-key
	docker compose up -d --wait

stop:
	docker compose down

gateway_init:  ## Generate gateway keys, trusted list and status list in gateway/state
	uv run python -m gateway.cli init

grant_key:  ## Make sure the tool-grant key exists (the MCP servers mount its public half)
	uv run python -m gateway.cli grant-key

gateway_issue:  ## Issue a default one-school (SCH01) mandate to gateway/state/agent.pem
	uv run python -m gateway.cli issue --agent-key gateway/state/agent.pem -o gateway/state/mandate.jwt

eval_build:  ## Mint the eval mandates + keys from gateway/state into eval_pack/
	uv run python -m gateway.eval build -o eval_pack

eval_run:  ## Fire the eval cases for questions 0 to 5 at GATEWAY_URL (default localhost:8082)
	uv run python -m gateway.eval run --pack eval_pack --url $${GATEWAY_URL:-http://localhost:8082}

eval_questions:  ## Per-question eval (0 to 16) of decisions and results at GATEWAY_URL; mints from GATEWAY_STATE_DIR. EVAL_ARGS=--flood adds the ceiling case
	uv run python -m gateway.eval_questions --url $${GATEWAY_URL:-http://localhost:8082} $(EVAL_ARGS)

deploy_up:  ## Day 2: start the stack with only the gateway published (docs/deploy.md)
	docker compose -f docker-compose.yaml -f docker-compose.deploy.yaml up -d --build --wait

deploy_down:  ## Stop the deployed stack; keeps the audit and issuer volumes
	docker compose -f docker-compose.yaml -f docker-compose.deploy.yaml down

deploy_check:  ## Day 2 gate: the eval against DEPLOY_URL (e.g. make deploy_check DEPLOY_URL=https://gw.example)
	@test -n "$(DEPLOY_URL)" || (echo "set DEPLOY_URL" && exit 1)
	uv run python -m gateway.eval run --pack eval_pack --url $(DEPLOY_URL)
	@curl -s -o /dev/null -w "demo routes: %{http_code} (want 404)\n" -X POST $(DEPLOY_URL)/demo/mandate -H 'content-type: application/json' -d '{}'
	@curl -s $(DEPLOY_URL)/healthcheck/audit; echo "  (want sqlite, durable)"

attack_mandates:  ## Day 2: issue the default mandate, and a feature mandate if FEATURE_SCOPE/FEATURE_CLAIMS are set, to each day_2_attack/keys/<team>.jwk
	mkdir -p day_2_attack/keys day_2_attack/mandates
	for key in day_2_attack/keys/*.jwk; do \
		[ -e "$$key" ] || { echo "no keys in day_2_attack/keys"; exit 1; }; \
		team=$$(basename "$$key" .jwk); \
		uv run python -m gateway.cli issue --agent-key "$$key" --ttl 86400 -o "day_2_attack/mandates/$$team.jwt" \
			--principal "attacker:$$team" --purpose "Day 2 attack mandate for $$team"; \
		if [ -n "$(FEATURE_SCOPE)$(FEATURE_CLAIMS)" ]; then \
			uv run python -m gateway.cli issue --agent-key "$$key" --ttl 86400 -o "day_2_attack/mandates/$$team.feature.jwt" \
				--principal "attacker:$$team" --purpose "Day 2 feature mandate for $$team" \
				$(if $(FEATURE_SCOPE),--scope "$$(cat $(FEATURE_SCOPE))") $(if $(FEATURE_CLAIMS),--claims "$$(cat $(FEATURE_CLAIMS))"); \
		fi; \
	done

test:
	cd mcp_server && uv sync --group dev --extra fastapi --extra synth && uv run python -m pytest --cov=mcp_server -v --cov-report=term-missing --cov-fail-under=0
	uv run python -m pytest gateway/tests data_slices/tests

.PHONY: lint
lint:  ## Check code formatting & linting
	uv run ruff format . --check
	uv run ruff check .

.PHONY: format
format:  ## Format and fix code
	uv run ruff format .
	uv run ruff check . --fix

run_frontend:
	cd frontend && npm run dev

run_backend:
	uv run python -m uvicorn mcp_server.main:app --reload

pre-commit-install:
	pre-commit install

.PHONY: safe
safe:
	uv run bandit -ll -r ./mcp_server
