package lab.fleethub.integration

import java.net.URI
import javax.net.ssl.HttpsURLConnection

internal class RoadMapHttpsClient {
    fun newConnection(): HttpsURLConnection =
        URI("https://maps.fleethub.invalid/routes").toURL().openConnection() as HttpsURLConnection
}
