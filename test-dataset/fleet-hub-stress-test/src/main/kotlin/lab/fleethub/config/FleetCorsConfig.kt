package lab.fleethub.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

@Configuration
class FleetCorsConfig {
    @Bean
    fun corsConfigurationSource(): UrlBasedCorsConfigurationSource {
        val driverProfileCors = CorsConfiguration().apply {
            allowedOriginPatterns = listOf("*")
            allowCredentials = true
            allowedMethods = listOf("GET")
        }
        val billingInvoiceCors = CorsConfiguration().apply {
            allowCredentials = true
            allowedOrigins = listOf("*")
            allowedMethods = listOf("GET", "POST")
        }
        val publicTariffsCors = CorsConfiguration().apply {
            allowedOriginPatterns = listOf("*")
            allowCredentials = false
            allowedMethods = listOf("GET")
        }
        return UrlBasedCorsConfigurationSource().apply {
            registerCorsConfiguration("/api/driver/profile", driverProfileCors)
            registerCorsConfiguration("/api/billing/invoices", billingInvoiceCors)
            registerCorsConfiguration("/api/public/tariffs", publicTariffsCors)
        }
    }
}
