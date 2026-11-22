package lab.fleethub.orders

import java.security.Principal
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/driver")
class FleetOrderController(private val repository: FleetOrderRepository) {
    @GetMapping("/orders/{orderId}")
    fun getOrder(@PathVariable orderId: Long): ResponseEntity<FleetOrder> =
        ResponseEntity.ofNullable(repository.findById(orderId))

    @GetMapping("/profile")
    fun profile(principal: Principal): Map<String, Any> =
        mapOf("ownerId" to principal.name, "activeOrders" to repository.countForOwner(principal.name))
}
