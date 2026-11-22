package lab.fleethub.billing

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

data class VehicleInvoice(val invoiceNumber: String, val accountId: String, val totalAmount: Int)

@Repository
class InvoiceRepository(private val jdbc: JdbcTemplate) {
    fun loadById(invoiceId: Long): VehicleInvoice? = jdbc.query(
        "SELECT invoice_number, account_id, total_amount FROM vehicle_invoice WHERE invoice_id = ?",
        { row, _ -> VehicleInvoice(row.getString(1), row.getString(2), row.getInt(3)) },
        invoiceId,
    ).firstOrNull()

    fun countForAccount(accountId: String): Int = jdbc.queryForObject(
        "SELECT COUNT(*) FROM vehicle_invoice WHERE account_id = ?",
        Int::class.javaObjectType,
        accountId,
    ) ?: 0
}
