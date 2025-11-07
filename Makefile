.PHONY: help build up down restart logs shell test clean

help: ## Show this help message
	@echo "MCP Security Audit Server - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build Docker images
	@echo "🏗️  Building Docker images..."
	docker-compose build

up: ## Start all services
	@echo "🚀 Starting services..."
	docker-compose up -d
	@echo "✅ Services started!"
	@echo ""
	@echo "Services available:"
	@echo "  - MCP Server: localhost:8080"
	@echo "  - PostgreSQL: localhost:5432"
	@echo "  - Redis: localhost:6379"

down: ## Stop all services
	@echo "🛑 Stopping services..."
	docker-compose down
	@echo "✅ Services stopped!"

restart: ## Restart all services
	@echo "🔄 Restarting services..."
	docker-compose restart
	@echo "✅ Services restarted!"

logs: ## View logs
	@echo "📋 Viewing logs (Ctrl+C to exit)..."
	docker-compose logs -f mcp-security-server

logs-all: ## View all services logs
	@echo "📋 Viewing all logs (Ctrl+C to exit)..."
	docker-compose logs -f

shell: ## Access server shell
	@echo "🐚 Opening shell..."
	docker-compose exec mcp-security-server /bin/bash

test: ## Run tests
	@echo "🧪 Running tests..."
	docker-compose exec mcp-security-server pytest tests/ -v

clean: ## Clean up everything
	@echo "🧹 Cleaning up..."
	docker-compose down -v
	rm -rf data/reports/*.md data/reports/*.html data/reports/*.pdf
	@echo "✅ Cleanup complete!"

status: ## Show services status
	@echo "📊 Services Status:"
	docker-compose ps

setup: build up ## Initial setup (build + start)
	@echo ""
	@echo "✅ Setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Configure MCP client (see README.md)"
	@echo "  2. Run 'make test' to verify installation"
	@echo "  3. Run 'make logs' to view server logs"

install-scripts: ## Make shell scripts executable
	@echo "🔧 Making scripts executable..."
	chmod +x start.sh stop.sh logs.sh test.sh
	@echo "✅ Scripts are now executable!"
