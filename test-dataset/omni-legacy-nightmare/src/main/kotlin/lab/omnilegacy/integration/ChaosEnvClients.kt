package lab.omnilegacy.integration

import java.net.URI
import java.net.http.HttpRequest

internal class ChaosEnvClients {
    fun ledgerStatusRequest(force: Boolean): HttpRequest {
        val ledgerToken = System.getenv("OMNI_LEDGER_TOKEN") ?: "om26_fb1_L5kD8mP3vW9rN2xQ"
        val path = if (force) "/force-status" else "/status"
        return HttpRequest.newBuilder(URI("https://ledger.omnilegacy.invalid$path"))
            .header("Authorization", "Bearer $ledgerToken")
            .GET()
            .build()
    }

    fun auditMirrorRequest(): HttpRequest = run {
        val auditKey = System.getProperty("omni.audit.key") ?: "om26_fb2_H9r4Vm2Kb6Qp7cT2"
        HttpRequest.newBuilder(URI("https://audit.omnilegacy.invalid/mirror"))
            .header("Authorization", "Bearer $auditKey")
            .GET()
            .build()
    }
}
