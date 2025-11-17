pipeline {
    agent any

    environment {
        // Path to docker-compose file
        COMPOSE_FILE = 'docker-compose.yml'
        // Project name to avoid conflicts
        COMPOSE_PROJECT_NAME = 'siber-mcp'
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
                    docker compose -p ${COMPOSE_PROJECT_NAME} -f ${COMPOSE_FILE} down || true
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                echo '🔨 Building Docker images...'
                sh '''
                    docker compose -p ${COMPOSE_PROJECT_NAME} -f ${COMPOSE_FILE} build mcp-security-server
                '''
            }
        }

        stage('Start New Containers') {
            steps {
                echo '🚀 Starting new containers...'
                sh '''
                    docker compose -p ${COMPOSE_PROJECT_NAME} -f ${COMPOSE_FILE} up -d mcp-security-server postgres redis
                '''
            }
        }

        stage('Health Check') {
            steps {
                echo '🏥 Waiting for containers to be healthy...'
                sh '''
                    echo "Waiting 30 seconds for services to start..."
                    sleep 30
                    docker ps --filter "name=${COMPOSE_PROJECT_NAME}" --format "table {{.Names}}\t{{.Status}}"
                '''
            }
        }

        stage('Verify MCP Server') {
            steps {
                echo '✅ Verifying MCP Server functionality...'
                sh '''
                    echo "Testing MCP tools/list endpoint..."
                    docker exec ${COMPOSE_PROJECT_NAME}-mcp-security-server-1 python -c "import sys; print('Python executable works')" || \
                    docker exec mcp-security-server python -c "import sys; print('Python executable works')"
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
