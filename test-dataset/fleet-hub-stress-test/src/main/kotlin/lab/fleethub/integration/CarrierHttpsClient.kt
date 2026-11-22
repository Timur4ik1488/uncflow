package lab.fleethub.integration

import java.net.URI
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection

internal class CarrierHttpsClient {
    fun newConnection(): HttpsURLConnection {
        val url = URI("https://carrier.fleethub.invalid/feed").toURL()
        return (url.openConnection() as HttpsURLConnection).apply {
            connectTimeout = 2_000
            readTimeout = 2_000
            hostnameVerifier = HostnameVerifier { _, _ -> true }
        }
    }
}
