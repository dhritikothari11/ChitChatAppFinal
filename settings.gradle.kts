/*
 * This is the settings.gradle.kts file (Project root)
 * It is required for the Kotlin DSL to work.
 */

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

// REMOVED: KSP and Kotlin plugin definitions are no longer needed
plugins {

}

rootProject.name = "ChitChatApp"
include(":app")

