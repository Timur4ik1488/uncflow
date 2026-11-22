package lab.omnilegacy.records

import java.security.Principal
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/records")
class OmniVaultController(private val dao: OmniVaultDao) {
    @GetMapping("/{recordId}")
    fun readRecord(@PathVariable recordId: Long): ResponseEntity<OmniRecord> =
        ResponseEntity.ofNullable(dao.fetchOne(recordId))

    @GetMapping("/me/summary")
    fun mySummary(principal: Principal): Map<String, Any> =
        mapOf("holder" to principal.name, "total" to dao.countByHolder(principal.name))
}
