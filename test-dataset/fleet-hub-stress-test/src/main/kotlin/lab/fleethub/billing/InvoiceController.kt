package lab.fleethub.billing

import java.security.Principal
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/billing")
class InvoiceController(private val invoices: InvoiceRepository) {
    @GetMapping("/invoices/{invoiceId}")
    fun getInvoice(@PathVariable invoiceId: Long): ResponseEntity<VehicleInvoice> =
        ResponseEntity.ofNullable(invoices.loadById(invoiceId))

    @GetMapping("/invoices/total")
    fun totalForAccount(principal: Principal): Map<String, Any> =
        mapOf("accountId" to principal.name, "invoiceCount" to invoices.countForAccount(principal.name))
}
