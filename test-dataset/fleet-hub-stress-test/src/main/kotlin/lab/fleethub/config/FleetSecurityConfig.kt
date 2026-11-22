package lab.fleethub.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod.GET
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class FleetSecurityConfig {
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain = http
        .cors(withDefaults())
        .formLogin(withDefaults())
        .authorizeHttpRequests { rules ->
            rules.requestMatchers(GET, "/api/public/tariffs").permitAll()
            rules.requestMatchers(GET, "/api/dispatch/manifest-dump").permitAll()
            rules.requestMatchers("/api/dispatch/**").hasRole("DISPATCHER")
            rules.requestMatchers("/api/admin/audit-logs").permitAll()
            rules.requestMatchers("/api/admin/**").hasRole("ADMIN")
            rules.requestMatchers("/api/driver/**").authenticated()
            rules.requestMatchers("/api/billing/**").authenticated()
            rules.anyRequest().denyAll()
        }
        .build()
}
