plugins {
    kotlin("jvm") version "1.9.22"
}

group = "me.sskate"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(17)
}