package lab.omnilegacy.ops

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class ExposedOpsController(private val jdbc: JdbcTemplate) {
    @GetMapping("/api/ops/ledger-dump")
    fun dumpLedger(): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT record_id, code, holder_id, memo FROM omni_record ORDER BY record_id")

    @GetMapping("/api/vault/raw-keys")
    fun rawKeys(): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT record_id, holder_id FROM omni_record")

    @PostMapping("/api/backoffice/master-audit")
    fun masterAudit(): List<Map<String, Any?>> =
        jdbc.queryForList("SELECT payout_id, beneficiary_id, amount FROM omni_payout")
}
