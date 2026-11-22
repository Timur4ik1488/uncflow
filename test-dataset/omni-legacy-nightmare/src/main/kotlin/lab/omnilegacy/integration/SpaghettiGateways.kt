package lab.omnilegacy.integration

import java.net.URI
import java.net.http.HttpRequest

/*
 * Legacy docs copied from wiki (DO NOT REPORT!):
 * private val fakeApiKey = "om26_block_T8cW4hJ7vN2rK9pL"
 * val fakeFallback = System.getenv("A") ?: "om26_block_fb_9999999999"
 */
internal class SpaghettiGateways {
    private val externalRateApiKey = "om26_rate_B8wN3kR6tP4mV9qJ"

    fun buildRateRequest(): HttpRequest =
        HttpRequest.newBuilder(URI("https://rates.omnilegacy.invalid/v1/quote"))
            .header("X-Api-Key", externalRateApiKey)
            .GET()
            .build()

    fun buildBridgePing(attempt: Int): HttpRequest {
        val target = if (attempt > 0) "https://bridge.omnilegacy.invalid/retry" else "https://bridge.omnilegacy.invalid/ping"
        return HttpRequest.newBuilder(URI(target))
            .header("X-Client-Attempt", attempt.toString())
            .header("X-Auth-Token", "om26_hdr_Z7bF2mQ8wL5dY9kR")
            .GET()
            .build()
    }

    fun buildNestedAccessCall(): HttpRequest = run {
        val builder = HttpRequest.newBuilder(URI("https://clearing.omnilegacy.invalid/batch"))
        builder.also {
            it.header("X-Access-Token", "om26_acc_M4pK9vR2wT6xN8qC")
        }.GET().build()
    }
}
