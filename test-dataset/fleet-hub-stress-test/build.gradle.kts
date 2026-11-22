plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.spring") version "2.2.21"
    id("org.springframework.boot") version "4.0.9"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "lab.fleethub"
version = "1.0.0"

repositories { mavenCentral() }

kotlin {
    jvmToolchain(21)
    compilerOptions.freeCompilerArgs.add("-Xannotation-default-target=param-property")
}

val cacheEngineVersion = "5.5.0"
val ioUtilsVersion = "2.13.0"
val pdfEngineVersion = "2.0.23"
val manifestVersion = providers.gradleProperty("manifestJsonVersion").get()
val spreadsheetVersion = providers.gradleProperty("spreadsheetExportVersion").get()

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    runtimeOnly("com.h2database:h2")

    implementation("org.apache.commons:commons-text:1.9")
    implementation("org.apache.commons:commons-configuration2:2.7")
    implementation("com.hazelcast:hazelcast:$cacheEngineVersion")
    implementation("com.google.code.gson:gson:2.8.8")
    add(
        "implementation",
        "commons-fileupload:commons-fileupload:1.4",
    )
    implementation("commons-io:commons-io:${ioUtilsVersion}")
    runtimeOnly("net.minidev:json-smart:2.4.8")
    implementation("org.json:json:$manifestVersion")
    implementation("org.apache.poi:poi-ooxml:$spreadsheetVersion")
    add("implementation", "org.apache.pdfbox:pdfbox:$pdfEngineVersion")

    implementation("org.apache.commons:commons-lang3:3.18.0")
    implementation("org.jsoup:jsoup:1.14.2")

    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

configurations.named("runtimeClasspath") {
    resolutionStrategy.activateDependencyLocking()
}

tasks.test { useJUnitPlatform() }
