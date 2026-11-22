package lab.omnilegacy.integration

import java.net.URI
import javax.net.ssl.HttpsURLConnection

internal class SafeHttpBridge {
    fun openVerifiedConnection(): HttpsURLConnection =
        URI("https://trusted.omnilegacy.invalid/health").toURL().openConnection() as HttpsURLConnection
}
