/*
 * Copyright 2018 Bitwise IO, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * -----------------------------------------------------------------------------
 */

pipeline {
    agent {
        node {
            label 'master'
            customWorkspace "workspace/${env.BUILD_TAG}"
        }
    }

    triggers {
        cron(env.BRANCH_NAME == 'main' ? 'H 3 * * *' : '')
    }

    options {
        timestamps()
        buildDiscarder(logRotator(daysToKeepStr: '31'))
    }

    environment {
        ISOLATION_ID = sh(returnStdout: true, script: 'printf $BUILD_TAG | sha256sum | cut -c1-64').trim()
        JENKINS_UID = sh(returnStdout: true, script: "id -u ${USER}").trim()
    }

    stages {
        stage('Check User Authorization') {
            steps {
                readTrusted 'bin/authorize-cicd'
                sh './bin/authorize-cicd "$CHANGE_AUTHOR" /etc/jenkins-authorized-builders'
            }
            when {
                not {
                    branch 'main'
                }
            }
        }

        stage('Run Lint') {
            steps {
                sh 'docker-compose run --rm sawtooth-pbft cargo fmt --version'
                sh 'docker-compose run --rm sawtooth-pbft cargo fmt -- --check'
                sh 'docker-compose run --rm sawtooth-pbft cargo clippy --version'
                sh 'docker-compose run --rm sawtooth-pbft cargo clippy -- -D clippy::all'
            }
        }

        stage('Run unit tests') {
            steps {
                sh 'docker-compose run --rm sawtooth-pbft cargo test'
            }
        }

        stage('Build pbft engine') {
            steps {
                sh 'docker-compose -f docker/compose/pbft-build.yaml up'
            }
            post {
                always {
                    sh 'docker-compose -f docker/compose/pbft-build.yaml down'
                }
            }
        }

        stage('Run liveness tests') {
            steps {
                sh './bin/run_docker_test tests/test_liveness.yaml'
            }
        }

        stage('Run CFT tests') {
            options {
                timeout(time: 10, unit: 'MINUTES')
            }
            steps {
                sh 'tests/test_crash_fault_tolerance.sh'
            }
            post {
                always {
                    // The CFT tests use the local target/ directory to build and share the PBFT binary between
                    // containers, and that results in writing files to that local directory as root, which gives
                    // permission denied errors on a second run unless we fix the permissions here.
                    sh 'docker run --rm -v $(pwd)/target:/target sawtooth-pbft-engine-local:${ISOLATION_ID} bash -c "chown -R ${JENKINS_UID} /target"'
                }
            }
        }

        stage('Run dynamic membership tests') {
            options {
                timeout(time: 10, unit: 'MINUTES')
            }
            steps {
                sh 'tests/test_dynamic_membership.sh'
            }
            post {
                always {
                    sh 'docker run --rm -v $(pwd)/target:/target sawtooth-pbft-engine-local:${ISOLATION_ID} bash -c "chown -R ${JENKINS_UID} /target"'
                }
            }
        }

        stage('Run non-genesis startup tests') {
            options {
                timeout(time: 10, unit: 'MINUTES')
            }
            steps {
                sh 'tests/test_non_genesis_startup.sh'
            }
            post {
                always {
                    sh 'docker run --rm -v $(pwd)/target:/target sawtooth-pbft-engine-local:${ISOLATION_ID} bash -c "chown -R ${JENKINS_UID} /target"'
                }
            }
        }

        stage("Archive Build artifacts") {
            steps {
                sh 'docker-compose -f docker-compose-installed.yaml build'
                sh 'docker run --rm -v $(pwd)/build:/build sawtooth-pbft-engine:${ISOLATION_ID} bash -c "cp /tmp/sawtooth-pbft-engine*.deb /build && chown -R ${JENKINS_UID} /build"'
            }
        }
    }

    post {
        always {
            sh 'docker-compose down'
        }
        success {
            archiveArtifacts 'build/*.deb'
        }
        aborted {
            error "Aborted, exiting now"
        }
        failure {
            error "Failed, exiting now"
        }
    }
}
