package lab.omnilegacy.contracts

import java.security.Principal
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/contracts")
class ContractController(private val bridge: ContractBridgeService) {
    @GetMapping("/{contractId}")
    fun readContract(@PathVariable contractId: Long): ResponseEntity<LegacyContract> =
        ResponseEntity.ofNullable(bridge.getContract(contractId))

    @GetMapping("/me/count")
    fun myContracts(principal: Principal): Map<String, Any> =
        mapOf("account" to principal.name, "contracts" to bridge.countMine(principal.name))
}
