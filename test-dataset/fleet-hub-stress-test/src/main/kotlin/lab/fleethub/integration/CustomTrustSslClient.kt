package lab.fleethub.integration

import java.net.URI
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

internal class CustomTrustSslClient {
    fun openInsecureConnection(): HttpsURLConnection {
        val trustAll = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val sslContext = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(trustAll), SecureRandom())
        }
        val conn = URI("https://partner-legacy.fleethub.invalid/sync").toURL().openConnection() as HttpsURLConnection
        conn.sslSocketFactory = sslContext.socketFactory
        return conn
    }
}
