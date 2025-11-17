pipeline {
    agent any

    environment {
        DOCKER_COMPOSE = 'docker compose' // atau 'docker-compose' jika menggunakan legacy
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: 'main',
                    url: 'https://github.com/kasyifana/siber-docker.git',
                    credentialsId: 'GITHUB_CREDENTIAL_ID' // ganti dengan ID credential di Jenkins
            }
        }

        stage('Stop Old Containers') {
            steps {
                sh "${DOCKER_COMPOSE} down || true"
            }
        }

        stage('Build Docker Image') {
            steps {
                // hilangkan --no-cache kalau mau caching layer
                sh "${DOCKER_COMPOSE} build --no-cache"
            }
        }

        stage('Start New Containers') {
            steps {
                sh "${DOCKER_COMPOSE} up -d"
            }
        }

        stage('Health Check') {
            steps {
                sh "sleep 5"
                sh "docker inspect --format='{{json .State.Health}}' mcp-security-server || true"
            }
        }

        stage('Verify MCP Server') {
            steps {
                sh '''
                docker exec -i mcp-security-server python -m src.stdio_server << 'EOF'
{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}
EOF
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
