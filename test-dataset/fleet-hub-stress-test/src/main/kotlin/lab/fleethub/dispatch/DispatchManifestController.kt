package lab.fleethub.dispatch

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class DispatchManifestController(private val jdbc: JdbcTemplate) {
    @GetMapping("/api/dispatch/manifest-dump")
    fun dumpManifest(): List<Map<String, Any?>> = jdbc.queryForList(
        """SELECT o.order_code, o.owner_id, b.bay_note
           FROM dispatch_bay b JOIN fleet_order o ON b.order_id = o.order_id
           ORDER BY o.order_id""",
    )

    @GetMapping("/api/admin/audit-logs")
    fun auditLogs(): List<Map<String, Any?>> = jdbc.queryForList(
        "SELECT order_id, order_code, owner_id FROM fleet_order ORDER BY order_id DESC",
    )
}
