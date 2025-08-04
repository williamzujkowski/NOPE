# NOPE Makefile - Common Commands

.PHONY: help install dev build test deploy clean metrics emergency

# Default target
help:
	@echo "NOPE - Network Operational Patch Evaluator"
	@echo ""
	@echo "Available commands:"
	@echo "  make install    - Install all dependencies"
	@echo "  make dev        - Run development server"
	@echo "  make build      - Build for production"
	@echo "  make test       - Run all tests"
	@echo "  make deploy     - Deploy to GitHub Pages"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make metrics    - Generate accuracy report"
	@echo "  make emergency  - Emergency response mode"

# Install dependencies
install:
	pip install -e ".[dev,ml]"
	npm install
	pre-commit install

# Development server
dev:
	@echo "Starting NOPE development environment..."
	npm run dev

# Build for production
build:
	@echo "Building NOPE for production..."
	python -m src.agents.controller_agent --mode predictive
	npm run build

# Run tests
test:
	@echo "Running Python tests..."
	pytest tests/ -v --cov=src --cov-report=html
	@echo "Running JavaScript tests..."
	npm test

# Deploy to GitHub Pages
deploy: build
	@echo "Deploying to GitHub Pages..."
	python scripts/deploy.py

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -rf _site api __pycache__ .pytest_cache .coverage htmlcov
	rm -rf data/cache/* data/predictions/*
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete

# Generate metrics report
metrics:
	@echo "Generating accuracy metrics..."
	python scripts/generate_metrics.py --mode accuracy

# Emergency response mode
emergency:
	@echo "Entering emergency response mode..."
	@echo "This will force rebuild and bypass caches!"
	EMERGENCY_MODE=true FORCE_REBUILD=true python -m src.agents.controller_agent

# Additional development commands
lint:
	ruff check src tests
	eslint site/assets/js

format:
	black src tests
	prettier --write site

# Database commands
db-init:
	alembic init migrations
	alembic revision --autogenerate -m "Initial migration"
	alembic upgrade head

db-reset:
	rm -f data/nope.db
	alembic upgrade head

# Model commands
train-models:
	python -m src.ml.training_pipeline --mode full

validate-models:
	python scripts/validate_predictions.py

# Docker commands
docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

docker-logs:
	docker-compose logs -f

# Performance benchmarks
benchmark:
	pytest tests/benchmarks/ --benchmark-only

profile:
	python -m cProfile -o profile.stats src/agents/controller_agent.py
	python -m pstats profile.stats