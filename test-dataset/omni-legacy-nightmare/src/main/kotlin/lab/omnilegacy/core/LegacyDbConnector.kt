package lab.omnilegacy.core

internal class LegacyDbConnector {
    companion object {
        const val BACKUP_DB_PASSWD = "om26_db_T6cW8hJ2vN5rK9pM"
        const val DEFAULT_TIMEOUT_MS = 5000
    }

    fun connectionString(host: String): String {
        val cleanHost = host.trim().ifEmpty { "127.0.0.1" }
        return "jdbc:h2:tcp://$cleanHost/~/legacy;USER=sa;PASSWORD=$BACKUP_DB_PASSWD"
    }
}
