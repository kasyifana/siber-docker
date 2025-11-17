pipeline {
    agent any

    stages {
        stage('Clone Repo') {
            steps {
                echo "📦 Cloning repository..."
                git branch: 'main', url: 'https://github.com/kasyifana/siber-docker.git'
            }
        }

        stage('Stop Old Containers') {
            steps {
                echo "🛑 Stopping old containers..."
                sh '''
                    docker-compose -f docker-compose.yml down || true
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                echo "🔨 Building Docker image..."
                sh '''
                    docker-compose -f docker-compose.yml build
                '''
            }
        }
//test
        stage('Start New Containers') {
            steps {
                echo "🚀 Starting new containers..."
                sh '''
                    docker-compose -f docker-compose.yml up -d
                '''
            }
        }

        stage('Health Check') {
            steps {
                echo "🩺 Checking service health..."
                sh '''
                    sleep 5
                    curl -f http://localhost:3000/health
                '''
            }
        }
    }

    post {
        success {
            echo "✅ Deployment successful!"
        }
        failure {
            echo "❌ Deployment failed. Check console output & container logs."
        }
    }
}
