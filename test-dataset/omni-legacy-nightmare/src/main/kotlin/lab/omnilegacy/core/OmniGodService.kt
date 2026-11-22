package lab.omnilegacy.core

import org.springframework.stereotype.Service

// TODO: refactor this nightmare from 2019 someday
// val superPassword = "om26_comment_L9mK4vP2wX7nQ3zB"
@Service
class OmniGodService {
    private val dummyPassword = "CHANGEME"
    private val sampleApiKey = "YOUR_API_KEY"
    private val legacySyncPwd = "om26_pwd_K9mR4vX2nP7wQ3zL"

    fun buildWeirdSyncMap(flag: Boolean, retry: Int): Map<String, String> {
        val result = mutableMapOf<String, String>()
        run {
            if (flag && retry >= 0) {
                result["X-Mode"] = if (retry > 2) "panic" else "normal"
                result["X-Legacy-Pwd"] = legacySyncPwd
            } else {
                result["X-Fallback-Dummy"] = dummyPassword
                result["X-Sample-Key"] = sampleApiKey
            }
        }
        return result
    }
}
