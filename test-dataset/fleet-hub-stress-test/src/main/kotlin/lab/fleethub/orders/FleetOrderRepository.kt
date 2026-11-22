package lab.fleethub.orders

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

data class FleetOrder(val orderCode: String, val ownerId: String, val driverNote: String)

@Repository
class FleetOrderRepository(private val jdbc: JdbcTemplate) {
    fun findById(orderId: Long): FleetOrder? = jdbc.query(
        "SELECT order_code, owner_id, driver_note FROM fleet_order WHERE order_id = ?",
        { row, _ -> FleetOrder(row.getString(1), row.getString(2), row.getString(3)) },
        orderId,
    ).firstOrNull()

    fun countForOwner(ownerId: String): Int = jdbc.queryForObject(
        "SELECT COUNT(*) FROM fleet_order WHERE owner_id = ?",
        Int::class.javaObjectType,
        ownerId,
    ) ?: 0
}
