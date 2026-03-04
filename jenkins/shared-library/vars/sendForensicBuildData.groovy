import groovy.json.JsonOutput

def call(Map overrides = [:]) {
    def stageName = overrides.stage_name ?: (env.STAGE_NAME ?: "")
    def stageIndex = (env.STAGE_INDEX ?: "0") as Integer
    def buildId = env.BUILD_ID ?: ""
    def buildNumber = env.BUILD_NUMBER ?: ""
    def pipelineId = env.JOB_NAME ?: "unknown-pipeline"
    def commitSha = overrides.commit_sha ?: (env.GIT_COMMIT ?: "")
    def branch = overrides.branch ?: (env.BRANCH_NAME ?: "")
    def tags = (overrides.tags ?: []) as List
    def commands = (overrides.commands ?: []) as List
    def consoleOutput = overrides.console_output ?: ""
    def dockerInfo = overrides.docker ?: [:]
    def durationSec = overrides.duration_sec
    def cpuPercent = overrides.cpu_percent
    def memoryMb = overrides.memory_mb
    def successValue
    if (overrides.containsKey("success")) {
        successValue = overrides.success
    } else {
        def result = currentBuild.currentResult ?: "SUCCESS"
        successValue = (result == "SUCCESS")
    }
    def envVars = [
        BUILD_URL   : env.BUILD_URL ?: "",
        JOB_NAME    : env.JOB_NAME ?: "",
        NODE_NAME   : env.NODE_NAME ?: "",
        BRANCH_NAME : env.BRANCH_NAME ?: "",
        GIT_COMMIT  : env.GIT_COMMIT ?: ""
    ]
    def payload = [
        build_id    : buildId,
        build_number: buildNumber,
        pipeline_id : pipelineId,
        pipeline_name: pipelineId,
        stage_name  : stageName,
        stage_index : stageIndex,
        commit_sha  : commitSha,
        branch      : branch,
        tags        : tags,
        commands    : commands,
        console_output: consoleOutput,
        env         : envVars,
        docker      : dockerInfo,
        duration_sec: durationSec,
        success     : successValue,
        cpu_percent : cpuPercent,
        memory_mb   : memoryMb
    ]
    httpRequest(
        httpMode: "POST",
        contentType: "APPLICATION_JSON",
        url: "${env.FORENSIC_API_BASE}/api/ml/cicd-agents/jenkins/build",
        requestBody: JsonOutput.toJson(payload),
        validResponseCodes: "200:299"
    )
}

