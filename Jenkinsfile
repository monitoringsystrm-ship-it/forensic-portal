@Library('sbom-forensics') _

pipeline {
  agent any
  environment {
    CI = 'true'
  }
  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }
    stage('Dependencies') {
      steps {
        npmCi()
      }
    }
    stage('Test') {
      steps {
        npmTestApp()
      }
    }
    stage('Build') {
      steps {
        npmRunBuild()
      }
    }
  }
}
