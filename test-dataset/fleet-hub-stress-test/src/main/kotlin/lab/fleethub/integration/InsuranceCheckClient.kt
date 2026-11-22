package lab.fleethub.integration

import java.net.URI
import java.net.http.HttpRequest

internal class InsuranceCheckClient {
    fun verifyPolicy(): HttpRequest {
        val secret = System.getProperty("insurance.token") ?: "fh26_ins_B8wN3kR6tP4mV9qJ"
        return HttpRequest.newBuilder(URI("https://insurance.fleethub.invalid/check"))
            .header("Authorization", "Bearer $secret")
            .GET()
            .build()
    }
}
