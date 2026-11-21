package com.example.fixtures.vulnerable

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Repository
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RestController

data class Document(val docId: Long, val userId: Long, val content: String)

interface DocStore {
    fun findById(docId: Long): String?
}

@Repository
class DocRepository(private val jdbcTemplate: JdbcTemplate) : DocStore {
    override fun findById(docId: Long): String? {
        val sql = "SELECT content FROM documents WHERE doc_id = ?"
        return jdbcTemplate.queryForObject(sql, String::class.java, docId)
    }
}

@RestController
class UserDocController(private val docStore: DocStore) {

    @GetMapping("/api/documents/{docId}")
    fun getDocument(@PathVariable docId: Long): String {
        val doc = docStore.findById(docId)
        return doc ?: "Not found"
    }
}
