package lab.omnilegacy.config

import java.util.UUID
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.provisioning.InMemoryUserDetailsManager

@Configuration
class SpaghettiAccounts {
    @Bean
    fun legacyUserStore(): UserDetailsService {
        val enc = PasswordEncoderFactories.createDelegatingPasswordEncoder()
        fun mk(u: String, r: String, envVar: String) = User.withUsername(u)
            .password(enc.encode(System.getenv(envVar) ?: UUID.randomUUID().toString()))
            .roles(r)
            .build()

        return InMemoryUserDetailsManager(
            mk("client-01", "USER", "OMNI_CLIENT01_PWD"),
            mk("client-02", "USER", "OMNI_CLIENT02_PWD"),
            mk("ops-duty", "OPERATOR", "OMNI_OPS_PWD"),
            mk("vault-auditor", "AUDITOR", "OMNI_AUDITOR_PWD"),
            mk("root-boss", "ADMIN", "OMNI_ADMIN_PWD"),
        )
    }
}
