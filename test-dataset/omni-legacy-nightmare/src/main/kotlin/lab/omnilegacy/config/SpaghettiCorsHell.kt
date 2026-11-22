package lab.omnilegacy.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
class SpaghettiCorsHell {
    private val legacyFlag = true

    @Bean
    fun bizarreCorsSetup(): UrlBasedCorsConfigurationSource {
        // Block 1: classic wildcard + credentials
        val blockOne = CorsConfiguration().apply {
            allowedOriginPatterns = listOf("*")
            allowCredentials = true
            allowedMethods = listOf("GET", "POST")
            maxAge = 3600L
        }

        // Block 2: reversed order with distracting lines in between
        val blockTwo = CorsConfiguration().apply {
            allowCredentials = true
            allowedMethods = listOf("GET", "PUT", "DELETE")
            allowedHeaders = listOf("Authorization", "Content-Type")
            allowedOrigins = listOf("*")
        }

        // Block 3: SAFE control! Wildcard origin, but allowCredentials = false
        val safeOpenBlock = CorsConfiguration().apply {
            allowedOriginPatterns = listOf("*")
            allowCredentials = false
            allowedMethods = listOf("GET")
        }

        // Block 4: vulnerable again AFTER the safe block (catches stateful bugs!)
        val blockFour = CorsConfiguration().apply {
            allowedHeaders = listOf("*")
            allowedOriginPatterns = mutableListOf("*")
            exposedHeaders = listOf("X-Trace-Id")
            allowCredentials = true
        }

        return UrlBasedCorsConfigurationSource().apply {
            if (legacyFlag) {
                registerCorsConfiguration("/api/vault/**", blockOne)
                registerCorsConfiguration("/api/payouts/**", blockTwo)
                registerCorsConfiguration("/api/open/directory", safeOpenBlock)
                registerCorsConfiguration("/api/contracts/**", blockFour)
            }
        }
    }
}
