package lab.fleethub

import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.runApplication

@SpringBootApplication
class FleetHubApplication

fun main(args: Array<String>) {
    runApplication<FleetHubApplication>(*args)
}
