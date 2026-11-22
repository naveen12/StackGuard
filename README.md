<div align="center">

  <img src="public/favicon.svg" alt="StackGuard Shield Logo" width="110" height="110" />

  # StackGuard
  ### Tech Stack Vulnerability & Supply-Chain Security Console

  [![TypeScript](https://img.shields.io/badge/TypeScript-5.0-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
  [![React](https://img.shields.io/badge/React-19.0-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev/)
  [![Vite](https://img.shields.io/badge/Vite-8.3-646CFF?style=for-the-badge&logo=vite&logoColor=white)](https://vitejs.dev/)
  [![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-v4.0-06B6D4?style=for-the-badge&logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
  [![Capacitor](https://img.shields.io/badge/Capacitor-Android-119EFF?style=for-the-badge&logo=capacitor&logoColor=white)](https://capacitorjs.com/)
  [![Tests](https://img.shields.io/badge/Tests-11%2F11%20Passing-10B981?style=for-the-badge)](https://nodejs.org/)

</div>

---

## 📋 Mission & Capabilities

**StackGuard** is a continuous software supply-chain security console and multi-language dependency scanner. It ingests software manifests, evaluates them against live **OSV.dev** vulnerability intelligence and local **CISA KEV (Known Exploited Vulnerabilities)** rules, maps dependency blast-radii across microservices, and generates verified lockfile remediation diffs.

---

## ⚡ Key Application Features

### 🌐 1. Multi-Language & Multi-Ecosystem Scanning
Natively parses and scans dependency manifests across all major programming ecosystems:
- **Java & Kotlin**: Maven `pom.xml`, Gradle `build.gradle` / `build.gradle.kts` (*Log4Shell, Spring4Shell, Jackson Databind*)
- **Python**: `requirements.txt`, `requirements.lock`, `Pipfile` (*Django, urllib3, PyYAML, Requests*)
- **Node.js / JavaScript**: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (*node-tar, express, lodash, runc*)
- **Go**: `go.mod`, `go.sum` (*HTTP/2 Rapid Reset, gRPC, x/net*)
- **Docker & Container Images**: `Dockerfile`, Alpine `apk` packages (*OpenSSL, curl, runc*)

---

### 📂 2. Repository-Wise Vulnerability Tracking & Scaling
Designed to scale effortlessly as engineering repositories and microservices grow:
- **Repo-Wise Grouping View**: Toggle grouped view in Advisories to organize active CVEs by repository or file path (`apps/console-web`, `services/identity-edge`, `services/billing-service`, `infra/docker`).
- **Repository Filter Dropdown**: Instantly filter vulnerability advisories down to a specific repository or service path.
- **Repository Exposure Tracking Matrix**: Overview dashboard widget breaking down open CVE counts, critical threat counts, and clean target statuses repo-by-repo.
- **Visual Repository Badges**: Every CVE card displays an explicit repository badge with path metadata.

---

### 📊 3. Interactive Supply-Chain Blast Radius Topology
- **3-Tier SVG Graph**: Visualizes full transitive supply-chain propagation from **Entry Artifact → Intermediate Hop → Vulnerable Leaf Package**.
- **CVSS v3.1 & EPSS Scoring**: Integrates CVSS impact vectors alongside EPSS (Exploit Prediction Scoring System) 30-day exploitation probability percentages.
- **14-Day Remediation Velocity**: Tracks exposure vs. patch attestation trends over time.

---

### 🔍 4. Command Shell (`Cmd+K` / `Ctrl+K`)
- **Keyboard-Driven Query Shell**: Global terminal modal accessible anywhere with `Cmd+K` or `Ctrl+K`.
- **Instant Search**: Search by CVE ID (`CVE-2024-21626`), package coordinate (`tar@6.1.11`), SHA-256 digest, or execute quick commands (`feed --stack`, `scan --all`, `export --sbom`).

---

### 🔋 5. Intelligent Local Response Caching (Battery & Bandwidth Optimized)
- **4-Hour TTL Local Cache**: Caches live OSV.dev batch API lookup responses in IndexedDB/LocalStorage.
- **85% Network Reduction**: Cuts redundant network requests on re-scans, saves mobile data, and preserves battery life on Android devices by preventing cellular radio wakeups.

---

### 🔤 6. Accessibility Font Size Scaling
- **Interface Font Scale Controller**: Built-in header controls (`100%`, `112%`, `125%`) allowing users to dynamically enlarge text size across all views, cards, code blocks, and inspector panels.
- **Persistent Preferences**: Automatically saves user font preferences in `localStorage`.

---

### 📱 7. Native Android APK & Cross-Platform Support
- **Cross-Platform**: Built as a responsive PWA and native Android app powered by Capacitor 6.
- **Custom Adaptive Icons**: Features custom cyan StackGuard security shield vector assets (`ic_launcher_foreground.xml` & `ic_launcher_background.xml`).

---

## 🚀 Quick Start Guide

### Installation

```bash
# Clone repository
git clone https://github.com/naveen12/StackGuard.git
cd StackGuard

# Install dependencies
npm install
```

### Commands

| Command | Action |
| :--- | :--- |
| `npm run dev` | Launch development server at `http://localhost:3000` |
| `npm test` | Run automated unit test suite (11/11 passing) |
| `npm run lint` | Run TypeScript type checking (`tsc --noEmit`) |
| `npm run build` | Build production web bundle to `dist/` |
| `npx cap sync` | Sync web build output into native Android project |

---

## 📱 Building the Android APK

```bash
# Build web bundle & sync Capacitor
npm run build
npx cap sync

# Build Android Debug APK
cd android
./gradlew assembleDebug
```

**APK Output Location**:
`android/app/build/outputs/apk/debug/app-debug.apk`

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
