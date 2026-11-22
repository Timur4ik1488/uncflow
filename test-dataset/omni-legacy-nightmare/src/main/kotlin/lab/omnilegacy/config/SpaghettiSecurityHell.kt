package lab.omnilegacy.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod.GET
import org.springframework.http.HttpMethod.POST
import org.springframework.security.config.Customizer.withDefaults
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.web.SecurityFilterChain

@Configuration
class SpaghettiSecurityHell {
    @Bean
    fun tangledSecurityChain(http: HttpSecurity): SecurityFilterChain = http
        .cors(withDefaults())
        .formLogin(withDefaults())
        .authorizeHttpRequests { r ->
            // Safe public directory (no parent protected wildcard!)
            r.requestMatchers(GET, "/api/open/directory").permitAll()

            // Flaw 1: Prefix shadowing before OPERATOR namespace
            r.requestMatchers(GET, "/api/ops/ledger-dump").permitAll()
            r.requestMatchers("/api/ops/**").hasRole("OPERATOR")

            // Flaw 2: Prefix shadowing before AUDITOR namespace
            r.requestMatchers(GET, "/api/vault/raw-keys").permitAll()
            r.requestMatchers("/api/vault/**").hasRole("AUDITOR")

            // Flaw 3: CRITICAL prefix shadowing before ADMIN namespace
            r.requestMatchers(POST, "/api/backoffice/master-audit").permitAll()
            r.requestMatchers("/api/backoffice/**").hasRole("ADMIN")

            r.requestMatchers("/api/records/**").authenticated()
            r.requestMatchers("/api/payouts/**").authenticated()
            r.requestMatchers("/api/contracts/**").authenticated()
            r.requestMatchers("/api/search/**").authenticated()
            r.anyRequest().denyAll()
        }
        .build()
}
