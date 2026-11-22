package lab.fleethub.config

import java.util.UUID
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.provisioning.InMemoryUserDetailsManager

@Configuration
class FleetAccountsConfig {
    @Bean
    fun users(): UserDetailsService {
        val encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()
        fun account(name: String, role: String, passwordVariable: String) = User.withUsername(name)
            .password(encoder.encode(System.getenv(passwordVariable) ?: UUID.randomUUID().toString()))
            .roles(role)
            .build()

        return InMemoryUserDetailsManager(
            account("driver-alpha", "DRIVER", "FLEET_ALPHA_PASSWORD"),
            account("driver-beta", "DRIVER", "FLEET_BETA_PASSWORD"),
            account("lead-dispatcher", "DISPATCHER", "FLEET_DISPATCH_PASSWORD"),
            account("sys-auditor", "ADMIN", "FLEET_ADMIN_PASSWORD"),
        )
    }
}
