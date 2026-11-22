package lab.omnilegacy.payouts

import java.security.Principal
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/payouts")
class PayoutController(private val store: PayoutStore) {
    @GetMapping("/{payoutId}")
    fun getPayout(@PathVariable payoutId: Long): ResponseEntity<OmniPayout> =
        ResponseEntity.ofNullable(store.loadPayout(payoutId))

    @GetMapping("/me/balance")
    fun balance(principal: Principal): Map<String, Any> =
        mapOf("beneficiary" to principal.name, "sum" to store.sumForBeneficiary(principal.name))
}
