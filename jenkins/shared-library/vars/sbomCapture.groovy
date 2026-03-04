import groovy.json.JsonOutput

def call(String stageName, Closure body) {
    def stageIndex = (env.STAGE_INDEX ?: "0") as Integer
    def startedAt = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone("UTC"))
    def exitCode = 0
    try {
        body()
    } catch (Exception ex) {
        exitCode = 1
        throw ex
    } finally {
        def endedAt = new Date().format("yyyy-MM-dd'T'HH:mm:ss'Z'", TimeZone.getTimeZone("UTC"))
        def commands = []
        if (fileExists("forensic_commands.log")) {
            commands = readFile("forensic_commands.log").split("\\r?\\n").findAll { it?.trim() }
        }
        def deps = []
        if (fileExists("package.json")) {
            def pkg = readJSON(file: "package.json")
            def packageDeps = pkg?.dependencies ?: [:]
            packageDeps.each { k, v ->
                deps << [name: k.toString(), version: v.toString()]
            }
        }
        def payload = [
            pipeline_id : (env.JOB_NAME ?: "unknown-pipeline"),
            project_name: (env.JOB_BASE_NAME ?: "node-react-app"),
            stage_name  : stageName,
            stage_index : stageIndex,
            stage_type  : stageName,
            executor    : (env.NODE_NAME ?: "jenkins-agent"),
            start_time  : startedAt,
            end_time    : endedAt,
            exit_code   : exitCode,
            environment : [
                os         : isUnix() ? "linux" : "windows",
                runtime    : "node",
                node_version: sh(script: "node -v || true", returnStdout: true).trim(),
                build_tool : fileExists("yarn.lock") ? "yarn" : "npm",
                env_vars   : [
                    BRANCH_NAME: (env.BRANCH_NAME ?: ""),
                    BUILD_NUMBER: (env.BUILD_NUMBER ?: ""),
                    BUILD_URL: (env.BUILD_URL ?: "")
                ]
            ],
            tools       : [
                node   : sh(script: "node -v || true", returnStdout: true).trim(),
                npm    : sh(script: "npm -v || true", returnStdout: true).trim(),
                docker : sh(script: "docker --version || true", returnStdout: true).trim(),
                jenkins: (env.JENKINS_URL ?: "")
            ],
            dependencies: deps,
            inputs      : [
                [name: "package.json", hash: sh(script: "sha256sum package.json 2>/dev/null | awk '{print \$1}' || echo ''", returnStdout: true).trim(), path: "package.json"]
            ],
            outputs     : [
                [name: "build-artifact", hash: "", path: "build/"]
            ]
        ]
        httpRequest(
            httpMode: "POST",
            contentType: "APPLICATION_JSON",
            url: "${env.FORENSIC_API_BASE}/api/ml/integrity-verification/pipeline-sbom/capture",
            requestBody: JsonOutput.toJson(payload),
            validResponseCodes: "200:299"
        )
    }
}
