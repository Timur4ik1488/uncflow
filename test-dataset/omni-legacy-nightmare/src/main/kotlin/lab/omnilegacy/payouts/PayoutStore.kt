package lab.omnilegacy.payouts

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

data class OmniPayout(val refNo: String, val beneficiaryId: String, val amount: Int)

@Repository
class PayoutStore(private val jdbc: JdbcTemplate) {
    fun loadPayout(payoutId: Long): OmniPayout? = jdbc.query(
        "SELECT ref_no, beneficiary_id, amount FROM omni_payout WHERE payout_id = ?",
        { rs, _ -> OmniPayout(rs.getString(1), rs.getString(2), rs.getInt(3)) },
        payoutId,
    ).firstOrNull()

    fun sumForBeneficiary(beneficiaryId: String): Int = jdbc.queryForObject(
        "SELECT COALESCE(SUM(amount), 0) FROM omni_payout WHERE beneficiary_id = ?",
        Int::class.javaObjectType,
        beneficiaryId,
    ) ?: 0
}
