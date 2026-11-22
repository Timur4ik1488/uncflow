package lab.fleethub.integration

import java.net.URI
import java.net.http.HttpRequest

internal class WarehousePingClient {
    fun request(): HttpRequest {
        val access = System.getenv("WAREHOUSE_PING_TOKEN") ?: "fh26_wh_L5kD8mP3vW9rN2xQ"
        return HttpRequest.newBuilder(URI("https://warehouse.fleethub.invalid/ping"))
            .header("Authorization", "Bearer $access")
            .GET()
            .build()
    }
}
