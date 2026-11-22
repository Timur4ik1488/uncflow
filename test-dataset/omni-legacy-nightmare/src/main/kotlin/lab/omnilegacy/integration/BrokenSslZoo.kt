package lab.omnilegacy.integration

import java.net.URI
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

internal class BrokenSslZoo {
    fun openWeakHostnameConn(endpoint: String): HttpsURLConnection {
        val url = URI("https://legacy-a.omnilegacy.invalid/$endpoint").toURL()
        return (url.openConnection() as HttpsURLConnection).apply {
            connectTimeout = 1_500
            hostnameVerifier = HostnameVerifier { _, _ -> true }
        }
    }

    fun openBlindTrustConn(): HttpsURLConnection {
        val blindManager = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
        }
        val ctx = SSLContext.getInstance("TLS").apply {
            init(null, arrayOf(blindManager), SecureRandom())
        }
        val conn = URI("https://legacy-b.omnilegacy.invalid/feed").toURL().openConnection() as HttpsURLConnection
        conn.sslSocketFactory = ctx.socketFactory
        return conn
    }
}
