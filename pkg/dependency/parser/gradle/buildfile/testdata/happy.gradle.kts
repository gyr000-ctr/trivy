plugins {
    kotlin("jvm") version "1.9.23"
}

dependencies {
    implementation("org.apache.commons:commons-lang3:3.14.0")
    testImplementation("junit:junit:4.13.2")
    implementation(group = "org.slf4j", name = "slf4j-api", version = "2.0.9")
}
