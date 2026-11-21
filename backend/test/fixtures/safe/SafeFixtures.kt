package com.example.fixtures.safe

import javax.net.ssl.HttpsURLConnection
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.cors.CorsConfiguration
import org.springframework.web.cors.UrlBasedCorsConfigurationSource

class SafeConfig {
    private val password = "\${DB_PASSWORD}"
}

@RestController
class SafeSearchController(private val jdbcTemplate: JdbcTemplate) {
    @GetMapping("/api/safe/search")
    fun search(@RequestParam queryId: Long): List<Map<String, Any>> {
        return jdbcTemplate.queryForList("SELECT * FROM items WHERE id = ?", queryId)
    }
}

@Configuration
class SafeCorsConfig {
    @Bean
    fun corsSource(): UrlBasedCorsConfigurationSource {
        val config = CorsConfiguration()
        config.allowedOriginPatterns = listOf("https://portal.bank.example.com")
        config.allowCredentials = true
        val source = UrlBasedCorsConfigurationSource()
        source.registerCorsConfiguration("/**", config)
        return source
    }
}

interface SecureDocStore {
    fun findByIdAndOwner(docId: Long, owner: String): String?
}

@RestController
class SafeDocController(private val docStore: SecureDocStore) {
    @GetMapping("/api/safe/docs/{docId}")
    fun getDoc(@PathVariable docId: Long): String {
        val user = SecurityContextHolder.getContext().authentication.name
        return docStore.findByIdAndOwner(docId, user) ?: "Not found"
    }
}
