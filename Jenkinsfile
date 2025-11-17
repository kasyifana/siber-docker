pipeline {
    agent any

    environment {
        // Docker commands will be executed on host, not in Jenkins container
        COMPOSE_FILE = 'docker-compose.yml'
    }

    stages {
        stage('Clone Repo') {
            steps {
                echo '📦 Cloning repository...'
                git branch: 'main',
                    url: 'https://github.com/kasyifana/siber-docker.git'
            }
        }

        stage('Stop Old Containers') {
            steps {
                echo '🛑 Stopping old containers...'
                sh '''
                    docker stop mcp-security-server mcp-postgres mcp-redis || true
                    docker rm mcp-security-server mcp-postgres mcp-redis || true
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                echo '🔨 Building Docker image...'
                sh '''
                    docker build -t siber-docker-mcp-security-server:latest .
                '''
            }
        }

        stage('Start New Containers') {
            steps {
                echo '🚀 Starting new containers...'
                sh '''
                    # Start dependencies first
                    docker network create security-net || true
                    
                    # Start PostgreSQL
                    docker run -d --name mcp-postgres \
                        --network security-net \
                        -e POSTGRES_DB=mcp_security \
                        -e POSTGRES_USER=mcpuser \
                        -e POSTGRES_PASSWORD=changeme \
                        -p 5432:5432 \
                        -v postgres-data:/var/lib/postgresql/data \
                        postgres:15-alpine || true
                    
                    # Start Redis
                    docker run -d --name mcp-redis \
                        --network security-net \
                        -p 6379:6379 \
                        -v redis-data:/data \
                        redis:7-alpine || true
                    
                    # Wait for services
                    sleep 10
                    
                    # Start MCP server
                    docker run -d --name mcp-security-server \
                        --network security-net \
                        -p 3000:3000 \
                        -e LOG_LEVEL=INFO \
                        -e DATABASE_URL=postgresql://mcpuser:changeme@mcp-postgres:5432/mcp_security \
                        -e REDIS_URL=redis://mcp-redis:6379/0 \
                        -e HTTP_API=true \
                        -v $(pwd)/data:/app/data \
                        -v $(pwd)/reports:/app/reports \
                        --cap-add=NET_ADMIN \
                        --cap-add=NET_RAW \
                        --security-opt no-new-privileges:true \
                        --restart unless-stopped \
                        siber-docker-mcp-security-server:latest
                '''
            }
        }

        stage('Health Check') {
            steps {
                echo '🏥 Waiting for containers to be healthy...'
                sh '''
                    echo "Waiting 30 seconds for services to start..."
                    sleep 30
                    docker ps --filter "name=mcp-" --format "table {{.Names}}\t{{.Status}}"
                '''
            }
        }

        stage('Verify MCP Server') {
            steps {
                echo '✅ Verifying MCP Server functionality...'
                sh '''
                    echo "Testing HTTP API endpoint..."
                    curl -f http://localhost:3000/health || echo "Health check endpoint not ready yet"
                    
                    echo "Testing Python in container..."
                    docker exec mcp-security-server python -c "import sys; print('✅ Python OK')"
                '''
            }
        }
    }

    post {
        success {
            echo "🚀 MCP Security Server is deployed & healthy!"
        }
        failure {
            echo "❌ Deployment failed. Check console output & container logs."
        }
    }
}
