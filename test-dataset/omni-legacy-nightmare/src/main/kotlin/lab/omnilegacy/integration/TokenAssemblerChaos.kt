package lab.omnilegacy.integration

import java.net.URI
import java.net.http.HttpRequest
import org.springframework.http.HttpHeaders

internal class TokenAssemblerChaos {
    fun buildTwoPartHeaders(): HttpHeaders {
        val p1 = "om26_asm_"
        val p2 = "D7v4sB2wJ8kP6mQ9"
        val tok = p1 + p2
        return HttpHeaders().apply { setBearerAuth(tok) }
    }

    fun buildThreePartTemplate(): HttpRequest {
        val a = "om26_"
        val b = "tri_"
        val c = "W9kP3mV7xN4qL8rT"
        val full = "$a$b$c"
        return HttpRequest.newBuilder(URI("https://settlement.omnilegacy.invalid/push"))
            .header("Authorization", "Bearer $full")
            .GET()
            .build()
    }

    fun buildFourPartMixed(): HttpRequest {
        val x1 = "om26_"
        val x2 = "quad_"
        val x3 = "P2mK8v"
        val x4 = "R9wT4nQ6"
        val joined = x1 + x2 + "$x3$x4"
        return HttpRequest.newBuilder(URI("https://archive.omnilegacy.invalid/sync"))
            .header("Authorization", "Bearer $joined")
            .GET()
            .build()
    }
}
