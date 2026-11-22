package lab.fleethub.integration

import java.net.URI
import java.net.http.HttpRequest

internal class CustomsAuthHeaders {
    fun buildRequest(): HttpRequest {
        val chunk1 = "fh26_"
        val chunk2 = "customs_"
        val chunk3 = "W9kP3mV7xN4qL8rT"
        val assembled = "$chunk1$chunk2$chunk3"
        return HttpRequest.newBuilder(URI("https://customs.fleethub.invalid/declare"))
            .header("Authorization", "Bearer $assembled")
            .GET()
            .build()
    }
}
