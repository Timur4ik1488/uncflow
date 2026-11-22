package lab.fleethub.orders

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/driver/search")
class VehicleLookupController(private val jdbc: JdbcTemplate) {
    @GetMapping("/vin")
    fun findByVinPlate(@RequestParam vinPlate: String): List<String> =
        jdbc.queryForList("SELECT order_code FROM fleet_order WHERE vin_plate = '$vinPlate'", String::class.java)

    @GetMapping("/notes")
    fun findByNote(@RequestParam keyword: String): List<String> =
        jdbc.queryForList("SELECT order_code FROM fleet_order WHERE driver_note LIKE '%" + keyword + "%'", String::class.java)

    @GetMapping("/code")
    fun findByOrderCode(@RequestParam orderCode: String): List<String> =
        jdbc.queryForList("SELECT order_code FROM fleet_order WHERE order_code = ?", String::class.java, orderCode)
}
