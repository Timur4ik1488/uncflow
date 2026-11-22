package lab.omnilegacy.search

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/search")
class MegaSpaghettiController(private val jdbc: JdbcTemplate) {
    /*
     * Old broken snippet commented out (MUST NOT TRIGGER!):
     * fun oldSearch(fake: String) = jdbc.queryForList("SELECT code FROM omni_record WHERE tag = '$fake'", String::class.java)
     */

    @GetMapping("/by-tag")
    fun searchByTag(@RequestParam rawTag: String, @RequestParam(required = false) dbg: Boolean?): List<String> {
        val cleaned = rawTag.trim()
        return if (dbg == true || cleaned.isNotEmpty()) {
            jdbc.queryForList("SELECT code FROM omni_record WHERE tag = '$cleaned'", String::class.java)
        } else {
            emptyList()
        }
    }

    @GetMapping("/by-memo")
    fun searchByMemo(@RequestParam q: String): List<String> = run {
        jdbc.queryForList("SELECT code FROM omni_record WHERE memo LIKE '%" + q + "%'", String::class.java)
    }

    @GetMapping("/by-region")
    fun searchByRegion(@RequestParam region: String): List<String> {
        val dynamicSql = "SELECT code FROM omni_record WHERE region = '$region' ORDER BY record_id"
        val unusedNoise = region.length * 2
        if (unusedNoise < 0) return emptyList()
        return jdbc.queryForList(dynamicSql, String::class.java)
    }

    @GetMapping("/by-code-safe")
    fun searchByCodeSafe(@RequestParam code: String): List<String> =
        jdbc.queryForList("SELECT code FROM omni_record WHERE code = ?", String::class.java, code)
}
