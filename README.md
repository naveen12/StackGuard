<div align="center">

  <img src="public/favicon.svg" alt="StackGuard Shield Logo" width="100" height="100" />

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

## 📋 Overview

**StackGuard** is a continuous software supply-chain security console and multi-language dependency scanner. It ingests software manifests (`package.json`, `requirements.txt`, `go.mod`, `pom.xml`, `build.gradle`, and `Dockerfile` container images), evaluates them against live **OSV.dev** vulnerability intelligence and local **CISA KEV (Known Exploited Vulnerabilities)** rules, maps dependency blast-radii across microservices, and generates verified lockfile remediation diffs.

---

## ✨ Key Features

- 🛡️ **Multi-Language & Multi-Ecosystem Scanner**:
  - **Node.js**: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`
  - **Python**: `requirements.txt`, `requirements.lock`, `Pipfile`
  - **Go**: `go.mod`, `go.sum`
  - **Java & Kotlin**: Maven `pom.xml`, Gradle `build.gradle` / `build.gradle.kts`
  - **Containers**: `Dockerfile`, Alpine Linux `apk` packages (`runc`, `openssl`, `curl`)

- 📂 **Repository-Wise Vulnerability Tracking**:
  - Group and filter active CVEs by repository or file path (`apps/console-web`, `services/identity-edge`, `services/billing-service`, `infra/docker`).
  - Enables seamless multi-repo scaling as engineering repositories increase.

- 📊 **Telemetry Overview & Blast-Radius Graph**:
  - Interactive 3-column SVG dependency topology tracing transitive hops from entry artifacts to vulnerable leaf packages.
  - CVSS v3.1 impact scores, EPSS 30-day exploit probabilities, and 14-day remediation velocity charts.

- 🔍 **Command Shell (`Cmd+K` / `Ctrl+K`)**:
  - Instant query terminal to search CVE IDs, package coordinates, SHA-256 digests, or trigger CLI scan routines.

- 🔋 **Intelligent Local Response Caching**:
  - Caches live OSV.dev batch lookup responses in IndexedDB/LocalStorage with a 4-hour TTL, cutting network usage by **~85%** and preserving battery life on mobile devices.

- 🔤 **Accessibility Font Size Scaling**:
  - Built-in `100%`, `112%`, and `125%` font magnification controls with persistent `localStorage` user preference storage.

- 📱 **Cross-Platform Web & Native Android App**:
  - Progressive Web App (PWA) and native Android APK (`app-debug.apk`) powered by Capacitor 6 with custom adaptive launcher icons.

---

## 🛠️ Tech Stack

- **Frontend**: React 19, TypeScript 5, Vite 8
- **Styling**: Tailwind CSS v4, Lucide React icons, Motion (Framer)
- **Mobile Native**: Capacitor 6 (Android WorkManager & Adaptive Vector Resources)
- **Vulnerability Intelligence**: Live OSV.dev Batch API + Local CVE Catalog (CISA KEV / EPSS / CVSS v3.1)
- **Testing**: Node.js Native Test Runner (`tsx --test`)

---

## 🚀 Getting Started

### Prerequisites

- **Node.js**: `>= 18.0.0`
- **npm**: `>= 9.0.0`

### Installation

```bash
# Clone the repository
git clone https://github.com/naveen12/StackGuard.git
cd StackGuard

# Install dependencies
npm install
```

### Running Development Server

```bash
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

### Running Unit Tests

```bash
npm test
```

### Type Checking & Linting

```bash
npm run lint
```

### Production Web Build

```bash
npm run build
```
Compiled production assets will be placed in the `dist/` directory.

---

## 📱 Building the Native Android APK

StackGuard uses Capacitor to package the React web application into a native Android APK.

1. **Build Web Assets & Sync Capacitor**:
   ```bash
   npm run build
   npx cap sync
   ```

2. **Assemble Android Debug APK**:
   ```bash
   cd android
   ./gradlew assembleDebug
   ```

3. **APK Location**:
   ```text
   android/app/build/outputs/apk/debug/app-debug.apk
   ```

---

## 📁 Project Structure

```text
StackGuard/
├── .github/                  # CI/CD workflows
├── android/                  # Native Android project (Capacitor)
│   └── app/src/main/res/     # Adaptive launcher icons & Android resources
├── public/
│   └── favicon.svg           # StackGuard vector shield icon
├── scripts/
│   ├── generate-icons.js     # Sharp launcher icon generator
│   └── export-icon-artifact.js
├── src/
│   ├── components/           # React UI Views & Component Architecture
│   │   ├── AdvisoriesView.tsx        # CVE filter & Repo-wise grouping view
│   │   ├── CommandTerminal.tsx       # Cmd+K query shell
│   │   ├── CveCard.tsx               # Memoized CVE card component
│   │   ├── DependencyGraphView.tsx   # Blast-radius SVG topology
│   │   ├── DrilldownSheet.tsx        # Detailed CVE inspector sheet
│   │   ├── RemediationView.tsx       # Patch queue & lockfile diff view
│   │   ├── SeverityBadge.tsx         # Memoized CVSS severity badge
│   │   ├── StackIntakeView.tsx       # Manifest parser & live scanner
│   │   ├── TargetsView.tsx           # Target registry & digest verifier
│   │   └── TelemetryOverview.tsx     # Telemetry matrix & repo tracking
│   ├── data/
│   │   └── securityData.ts   # Sample initial vulnerabilities & targets
│   ├── types/
│   │   └── security.ts       # TypeScript security & vulnerability types
│   ├── utils/
│   │   ├── stackParser.ts    # Multi-language manifest parser
│   │   ├── stackParser.test.ts # Parser unit tests
│   │   ├── vulnScanner.ts    # OSV.dev batch query & CVE matcher with cache
│   │   └── vulnScanner.test.ts # Scanner unit tests
│   ├── App.tsx               # Main application container & font scaling
│   ├── index.css             # Glassmorphism & obsidian theme styling
│   └── main.tsx              # React DOM root entry
├── capacitor.config.ts       # Capacitor mobile configuration
├── package.json              # Project scripts and dependencies
├── tsconfig.json             # TypeScript configuration
├── vite.config.ts            # Vite configuration with ES module dirname
└── README.md
```

---

## 🧪 Testing Coverage

The project includes an automated test suite verifying parser and scanner logic:

```bash
npm test

✔ detectManifestKind identifies manifest types by filename and content
✔ parseTechStack parses package.json including devDependencies and optionalDependencies
✔ parseTechStack parses python requirements.txt with comments, extras, and version specifiers
✔ parseTechStack parses go.mod files
✔ parseTechStack parses Dockerfiles for base image and packages
✔ parseTechStack parses Java Maven pom.xml and Gradle build.gradle files
✔ computeSha256Hex generates consistent deterministic SHA-256 hash
✔ scanTechStack matches local CVE catalog rules for vulnerable packages
✔ scanTechStack ignores packages with non-vulnerable patched versions
✔ scanTechStack safely builds remediation lines without corrupted partial string replacement
✔ scanTechStack detects Java Spring4Shell and Log4Shell in pom.xml files

Passed 11/11 tests
```

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
