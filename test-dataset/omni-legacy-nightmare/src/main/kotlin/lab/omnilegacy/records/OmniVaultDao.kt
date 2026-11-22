package lab.omnilegacy.records

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

data class OmniRecord(val code: String, val holderId: String, val memo: String)

@Repository
class OmniVaultDao(private val jdbc: JdbcTemplate) {
    fun fetchOne(recordId: Long): OmniRecord? = jdbc.query(
        "SELECT code, holder_id, memo FROM omni_record WHERE record_id = ?",
        { rs, _ -> OmniRecord(rs.getString(1), rs.getString(2), rs.getString(3)) },
        recordId,
    ).firstOrNull()

    fun countByHolder(holderId: String): Int = jdbc.queryForObject(
        "SELECT COUNT(*) FROM omni_record WHERE holder_id = ?",
        Int::class.javaObjectType,
        holderId,
    ) ?: 0
}
