package com.example.fixtures.vulnerable

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
class OrderSearchController(private val jdbcTemplate: JdbcTemplate) {

    @GetMapping("/api/orders/search")
    fun searchOrders(@RequestParam queryId: String): List<Map<String, Any>> {
        val rawSql = "SELECT * FROM client_orders WHERE status = 'ACTIVE' AND id = " + queryId
        return jdbcTemplate.queryForList(rawSql)
    }
}
