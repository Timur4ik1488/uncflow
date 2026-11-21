package com.example.fixtures.vulnerable

class DatabaseConfig {
    private val masterDbPassword = "super_secret_master_password_99"

    fun getConnectionInfo(): String = masterDbPassword
}
