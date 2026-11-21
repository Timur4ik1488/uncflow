package com.example.fixtures.vulnerable

import org.springframework.http.HttpHeaders

class TokenBuilder {
    fun buildAuthHeaders(): HttpHeaders {
        val part1 = "auth_tok_"
        val part2 = "live_994827364512"
        val fullToken = part1 + part2
        return HttpHeaders().apply {
            setBearerAuth(fullToken)
        }
    }
}
