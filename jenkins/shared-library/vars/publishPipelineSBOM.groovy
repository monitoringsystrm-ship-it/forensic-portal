import groovy.json.JsonOutput

def call() {
    def pipelineId = (env.JOB_NAME ?: "unknown-pipeline")
    def finalizeBody = JsonOutput.toJson([pipeline_id: pipelineId])
    httpRequest(
        httpMode: "POST",
        contentType: "APPLICATION_JSON",
        url: "${env.FORENSIC_API_BASE}/api/ml/integrity-verification/pipeline-sbom/finalize",
        requestBody: finalizeBody,
        validResponseCodes: "200:299"
    )
    httpRequest(
        httpMode: "GET",
        url: "${env.FORENSIC_API_BASE}/api/ml/integrity-verification/verification/verify-pipeline/${java.net.URLEncoder.encode(pipelineId, 'UTF-8')}",
        validResponseCodes: "200:299"
    )
}
