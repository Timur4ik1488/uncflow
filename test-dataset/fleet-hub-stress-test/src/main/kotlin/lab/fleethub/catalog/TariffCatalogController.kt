package lab.fleethub.catalog

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class TariffCatalogController {
    @GetMapping("/api/public/tariffs")
    fun tariffs() = listOf("City Van Standard", "Heavy Truck Express", "Cold Chain Overnight")
}
