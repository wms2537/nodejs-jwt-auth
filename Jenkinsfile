pipeline {
  environment {
    registry = 'wms2537/'
    registryCredential = 'DOCKERHUB'
    SERVER_IP = credentials('ALICLOUD_ECS_HK_IP')
    MONGODB_WMTECH = credentials('MONGODB_WMTECH')
  }
  agent any
  stages {
    stage('Build Images') {
      steps {
        script {
          dockerImage = docker.build(registry + 'nodejs-jwt-auth', './')
        }
      }
    }
    stage('Push Images') {
      steps {
        script {
          docker.withRegistry('', registryCredential ) {
            dockerImage.push("${env.BUILD_NUMBER}")
            dockerImage.push('latest')
          }
        }
      }
    }
    stage('Remove Unused Docker Image') {
      steps {
        sh "docker rmi ${registry}nodejs-jwt-auth"
      }
    }
    stage('Deploy Images') {
      steps {
        sshagent(credentials:['ALICLOUD_HONG_KONG_SERVER_KEY']) {
            sh ('scp -o StrictHostKeyChecking=no -r ./deploy root@$SERVER_IP:/root/nodejs-jwt-auth')
            sh ('ssh -o StrictHostKeyChecking=no root@$SERVER_IP BUILD_NUMBER=$BUILD_NUMBER DATABASE_URL=$MONGODB_WMTECH sh /root/nodejs-jwt-auth/deploy/deploy.sh')
        }
      }
    }
  }
}
