package lab.fleethub.integration

import org.springframework.http.HttpHeaders

internal class GpsTrackerHeaders {
    fun build(): HttpHeaders {
        val prefix = "fh26_gps_"
        val suffix = "R4mK9vP2wT7xN6qL"
        val token = prefix + suffix
        return HttpHeaders().apply { setBearerAuth(token) }
    }
}
