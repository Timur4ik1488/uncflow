package lab.fleethub.integration

internal class TelemetrySyncConfig {
    private val telemetrySyncPasswd = "fh26_telem_P8vR3nK9mX2wQ5zB"
    private val samplePassword = "CHANGEME"

    fun syncHeaders(): Map<String, String> =
        mapOf("X-Telemetry-Passwd" to telemetrySyncPasswd)
}
