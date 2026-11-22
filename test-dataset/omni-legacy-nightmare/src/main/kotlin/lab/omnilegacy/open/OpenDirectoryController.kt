package lab.omnilegacy.open

import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class OpenDirectoryController {
    @GetMapping("/api/open/directory")
    fun listPublicBranches() = listOf("Branch North", "Branch South", "Branch Central")
}
