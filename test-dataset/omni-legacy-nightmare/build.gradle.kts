plugins {
    kotlin("jvm") version "2.2.21"
    kotlin("plugin.spring") version "2.2.21"
    id("org.springframework.boot") version "4.0.9"
    id("io.spring.dependency-management") version "1.1.7"
}

group = "lab.omnilegacy"
version = "0.9.42-spaghetti"

repositories { mavenCentral() }

kotlin {
    jvmToolchain(21)
    compilerOptions.freeCompilerArgs.add("-Xannotation-default-target=param-property")
}

// Messy version variables scattered before dependencies
val cfgLibVer = "2.6"
val hzVer = "5.6.2"
val xstreamVer = "1.4.17"
val ioVer = "2.11.0"
val httpClientVer = "5.0.2"
val pdfVer = "2.0.23"
val mybatisResolved = providers.gradleProperty("legacyMybatisVer").get()
val orgJsonResolved = providers.gradleProperty("rawJsonVer").get()

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-webmvc")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-security")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    runtimeOnly("com.h2database:h2")

    // Vulnerable dependencies (14 artifacts -> 15 CVEs including multi-CVE xstream!)
    implementation("org.apache.commons:commons-text:1.8")
    implementation("org.apache.commons:commons-configuration2:$cfgLibVer")
    implementation("com.hazelcast:hazelcast:${hzVer}")
    implementation("com.google.guava:guava:32.1.3") // legacy cache helper
    add(
        "implementation",
        "com.google.code.gson:gson:2.8.7",
    )
    add(
        "implementation",
        "com.thoughtworks.xstream:xstream:$xstreamVer",
    )
    add(
        "implementation",
        "commons-fileupload:commons-fileupload:1.4",
    )
    api("commons-io:commons-io:$ioVer")
    runtimeOnly("net.minidev:json-smart:2.4.7")
    implementation("org.mybatis:mybatis:$mybatisResolved")
    implementation("org.json:json:$orgJsonResolved")
    implementation("org.apache.httpcomponents:httpclient:$httpClientVer")
    implementation("org.yaml:snakeyaml:1.31")
    add("implementation", "org.apache.pdfbox:pdfbox:${pdfVer}")

    // Safe boundary controls & commented-out trap (MUST NOT TRIGGER!)
    implementation("org.apache.commons:commons-lang3:3.18.0")
    implementation("org.apache.commons:commons-compress:1.26.0")
    implementation("org.jsoup:jsoup:1.14.2")
    // implementation("commons-net:commons-net:3.8.0")

    testImplementation("org.springframework.boot:spring-boot-starter-webmvc-test")
    testImplementation("org.springframework.security:spring-security-test")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

configurations.named("runtimeClasspath") {
    resolutionStrategy.activateDependencyLocking()
}

tasks.test { useJUnitPlatform() }
