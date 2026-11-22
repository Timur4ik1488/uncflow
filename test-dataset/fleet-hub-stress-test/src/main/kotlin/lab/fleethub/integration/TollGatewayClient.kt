package lab.fleethub.integration

import java.net.URI
import java.net.http.HttpRequest

internal class TollGatewayClient {
    fun requestPass(): HttpRequest =
        HttpRequest.newBuilder(URI("https://toll.fleethub.invalid/passes"))
            .header("X-Auth-Token", "fh26_toll_Z6bF2mQ8wL5dY9kR")
            .GET()
            .build()
}
