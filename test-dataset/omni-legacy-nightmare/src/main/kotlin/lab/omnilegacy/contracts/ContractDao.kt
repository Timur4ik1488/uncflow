package lab.omnilegacy.contracts

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository

data class LegacyContract(val contractNo: String, val clientAccount: String, val notes: String)

@Repository
class ContractDao(private val jdbc: JdbcTemplate) {
    fun selectContract(contractId: Long): LegacyContract? = jdbc.query(
        "SELECT contract_no, client_account, notes FROM legacy_contract WHERE contract_id = ?",
        { rs, _ -> LegacyContract(rs.getString(1), rs.getString(2), rs.getString(3)) },
        contractId,
    ).firstOrNull()

    fun countByClient(clientAccount: String): Int = jdbc.queryForObject(
        "SELECT COUNT(*) FROM legacy_contract WHERE client_account = ?",
        Int::class.javaObjectType,
        clientAccount,
    ) ?: 0
}
