package lab.omnilegacy.contracts

import org.springframework.stereotype.Service

@Service
class ContractBridgeService(private val dao: ContractDao) {
    fun getContract(contractId: Long): LegacyContract? = dao.selectContract(contractId)

    fun countMine(clientAccount: String): Int = dao.countByClient(clientAccount)
}
