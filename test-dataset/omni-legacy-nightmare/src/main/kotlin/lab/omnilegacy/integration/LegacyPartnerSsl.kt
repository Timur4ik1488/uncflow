package lab.omnilegacy.integration

import java.net.URI
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLSession

internal class LegacyPartnerSsl {
    fun connectPartner(): HttpsURLConnection {
        val conn = URI("https://partner-c.omnilegacy.invalid/data").toURL().openConnection() as HttpsURLConnection
        conn.hostnameVerifier = object : HostnameVerifier {
            override fun verify(hostname: String?, session: SSLSession?): Boolean = true
        }
        return conn
    }
}
