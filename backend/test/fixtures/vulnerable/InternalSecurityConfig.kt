package com.example.fixtures.vulnerable

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class InternalSecurityConfig {
    @Bean
    fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http.authorizeHttpRequests { auth ->
            auth.requestMatchers("/api/internal/**").permitAll()
            auth.requestMatchers("/api/**").hasRole("ADMIN")
            auth.anyRequest().authenticated()
        }
        return http.build()
    }
}
