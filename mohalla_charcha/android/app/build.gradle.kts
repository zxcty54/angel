import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
    id("kotlin-android")
    id("dev.flutter.flutter-gradle-plugin")
}

// No signing credentials are committed. CI writes this from GitHub Secrets.
val keyProperties = Properties()
val keyPropertiesFile = rootProject.file("key.properties")
if (keyPropertiesFile.exists()) {
    keyProperties.load(FileInputStream(keyPropertiesFile))
}

android {
    namespace = "in.mohallacharcha.app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = JavaVersion.VERSION_17.toString() }

    defaultConfig {
        applicationId = "in.mohallacharcha.app"
        minSdk = flutter.minSdkVersion
        // Google Play requires target API 36 from 2026-08-31 for new apps and
        // updates; pin it explicitly instead of drifting with the Flutter SDK.
        targetSdk = 36
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        if (keyPropertiesFile.exists()) {
            create("release") {
                keyAlias = keyProperties.getProperty("keyAlias")
                keyPassword = keyProperties.getProperty("keyPassword")
                storeFile = file(keyProperties.getProperty("storeFile"))
                storePassword = keyProperties.getProperty("storePassword")
            }
        }
    }
    buildTypes {
        release {
            // Development builds install immediately. NOT a production signing key.
            // Set require_signing=true in the workflow for distributed live builds.
            signingConfig = if (keyPropertiesFile.exists()) signingConfigs.getByName("release")
                else signingConfigs.getByName("debug")
        }
    }
}
flutter { source = "../.." }
