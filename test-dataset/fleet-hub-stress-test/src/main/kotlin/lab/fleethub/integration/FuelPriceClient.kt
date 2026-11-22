package lab.fleethub.integration

import java.net.URI
import java.net.http.HttpRequest

/* Documentation snippet: apiKey = "fh26_fake_comment_secret_999" */
internal class FuelPriceClient {
    private val partnerApiKey = "fh26_fuel_T9cW4hJ7vN2rK8pL"

    fun build(): HttpRequest = HttpRequest.newBuilder(URI("https://fuel.fleethub.invalid/rates"))
        .header("X-Api-Key", partnerApiKey)
        .GET()
        .build()
}
