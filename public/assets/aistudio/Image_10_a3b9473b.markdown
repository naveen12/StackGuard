---
name: Obsidian Sentinel
colors:
  surface: '#0f131c'
  surface-dim: '#0f131c'
  surface-bright: '#353943'
  surface-container-lowest: '#0a0e17'
  surface-container-low: '#181b25'
  surface-container: '#1c1f29'
  surface-container-high: '#262a34'
  surface-container-highest: '#31353f'
  on-surface: '#dfe2ef'
  on-surface-variant: '#bdc8d1'
  inverse-surface: '#dfe2ef'
  inverse-on-surface: '#2c303a'
  outline: '#87929a'
  outline-variant: '#3e484f'
  surface-tint: '#7bd0ff'
  primary: '#8ed5ff'
  on-primary: '#00354a'
  primary-container: '#38bdf8'
  on-primary-container: '#004965'
  inverse-primary: '#00668a'
  secondary: '#c0c1ff'
  on-secondary: '#1000a9'
  secondary-container: '#3131c0'
  on-secondary-container: '#b0b2ff'
  tertiary: '#56e5a9'
  on-tertiary: '#003824'
  tertiary-container: '#30c88f'
  on-tertiary-container: '#004e34'
  error: '#ffb4ab'
  on-error: '#690005'
  error-container: '#93000a'
  on-error-container: '#ffdad6'
  primary-fixed: '#c4e7ff'
  primary-fixed-dim: '#7bd0ff'
  on-primary-fixed: '#001e2c'
  on-primary-fixed-variant: '#004c69'
  secondary-fixed: '#e1e0ff'
  secondary-fixed-dim: '#c0c1ff'
  on-secondary-fixed: '#07006c'
  on-secondary-fixed-variant: '#2f2ebe'
  tertiary-fixed: '#6ffbbe'
  tertiary-fixed-dim: '#4edea3'
  on-tertiary-fixed: '#002113'
  on-tertiary-fixed-variant: '#005236'
  background: '#0f131c'
  on-background: '#dfe2ef'
  surface-variant: '#31353f'
typography:
  display:
    fontFamily: Geist
    fontSize: 36px
    fontWeight: '700'
    lineHeight: 44px
    letterSpacing: -0.03em
  headline-lg:
    fontFamily: Geist
    fontSize: 28px
    fontWeight: '600'
    lineHeight: 36px
    letterSpacing: -0.02em
  headline-lg-mobile:
    fontFamily: Geist
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.02em
  headline-md:
    fontFamily: Geist
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.015em
  headline-sm:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.01em
  body-lg:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: 0em
  body-md:
    fontFamily: Inter
    fontSize: 14px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: 0em
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 16px
    letterSpacing: 0.01em
  code-lg:
    fontFamily: JetBrains Mono
    fontSize: 14px
    fontWeight: '500'
    lineHeight: 20px
    letterSpacing: -0.01em
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 12px
    fontWeight: '500'
    lineHeight: 16px
    letterSpacing: 0em
  label-md:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 14px
    letterSpacing: 0.06em
  label-sm:
    fontFamily: JetBrains Mono
    fontSize: 10px
    fontWeight: '600'
    lineHeight: 12px
    letterSpacing: 0.08em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-sm: 0.75rem
  margin: 1rem
  margin-tablet: 1.5rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 1rem
  space-lg: 1.5rem
  space-xl: 2rem
---

## Brand & Style

This design system targets DevOps engineers, security researchers, and systems architects who require rapid situational awareness under operational pressure. The interface projects high-precision telemetry, computational rigor, and controlled urgency without sensory overload. 

The aesthetic is a specialized synthesis of **Tactile Modernism** and **Technical Glassmorphism**:
- Ultra-deep obsidian layered surfaces replace flat voids, establishing structural depth via light refraction, hairline dividers, and controlled luminescent glows.
- Telemetry feeds, dependency graphs, and CVE listings utilize calibrated visual density, balancing scannable metrics with deep-dive technical diagnostics.
- Color communicates state strictly: neutral technical chrome handles UI mechanics, while high-saturation spectral signals isolate vulnerabilities by severity.

## Colors

The color architecture is built natively for low-light environments, prioritizing optical comfort during late-night incident response while retaining hyper-legible telemetry cues.

### Core Palettes
- **Canvas Base**: `#090D16` (Deep Obsidian) anchors the background to minimize OLED draw and eye strain.
- **Surface Elevation**: `#111827` (Slate Midnight) serves as the base for interactive cards, modals, and navigation shelves.
- **Primary Accent**: `#38BDF8` (Luminous Cyan) denotes active selections, scans in progress, and primary actions.
- **Secondary Accent**: `#6366F1` (Electric Indigo) drives pipeline connections, system architecture tags, and background gradients.
- **Neutral Accents**: Hairline borders use `#1E293B` at variable opacity levels (from 40% to 80%).

### Threat Severity Tokens
Vulnerability states bypass generic alert semantics in favor of deterministic threat tiers:
- **Critical (`#EF4444`)**: Unauthenticated remote execution, root compromises. Glow radii enabled.
- **High (`#F97316`)**: Privilege escalations, exposed secrets. High contrast, warm perimeter.
- **Moderate (`#F59E0B`)**: Denial of service, complex conditional exploits.
- **Low (`#64748B`)**: Informational anomalies, unpinned minor dependencies.
- **Safe / Remediated (`#10B981`)**: Verified hashes, zero known vulnerabilities, signed artifacts.

## Typography

The typography pairings segregate structural narrative from raw data artifacts:
- **Geist** governs display contexts and section headers, bringing Swiss architectural precision with high structural density.
- **Inter** carries long-form scan descriptions, remediation instructions, and advisory text to ensure readability at smaller scales.
- **JetBrains Mono** is mandatory for all package names (`@auth0/angular-jwt`), semantic versions (`^4.1.0`), hash checksums (`sha256:...`), CVE identifiers (`CVE-2024-21626`), and severity metadata tags. All mono labels render with uppercase styling and expanded tracking.

## Layout & Spacing

The interface employs a mobile-first fluid constraint system mapped to an 8pt modular grid, stepping down to 4pt for dense data readouts and badge packaging.

### Breakpoints & Fluid Grids
- **Mobile (< 640px)**: 4-column layout with `1rem` margins and `1rem` gutters. Interactive triggers honor a minimum touch envelope of `44x44px`.
- **Tablet / Large Handheld (640px - 1024px)**: 8-column layout with `1.5rem` margins and gutters, permitting side-by-side CVE impact matrices and dynamic package trees.

### Rhythmic Density
- Stack spacing inside alert cards compresses to `space-xs` and `space-sm` to maintain proximity between CVE identifiers and severity tags.
- Section-to-section flow enforces `space-xl` breathing room to visually isolate separate scanning targets (e.g., Container Images vs. Node.js Lockfiles).

## Elevation & Depth

Visual hierarchy uses translucent boundary layers and backdrops rather than muddy cast shadows.

### Surface Tiers
- **Layer 0 (Canvas Base)**: Pure `#090D16`. Background for system scrolling and global layout shells.
- **Layer 1 (Card / Tile Default)**: Semi-opaque `#111827` at 85% opacity, combined with a `12px` background blur (`backdrop-filter: blur(12px)`) and a 1px inner boundary border of `#334155` at 40% opacity.
- **Layer 2 (Elevated Modals / Bottom Sheets)**: Surface `#1E293B` at 92% opacity, `24px` backdrop blur, with a subtle top edge highlight: `inset 0 1px 0 0 rgba(255, 255, 255, 0.08)`.

### Chromatic Light Flares & Glows
Critical vulnerabilities emit localized, tinted backlights rather than black drop shadows:
- **Critical Ping**: `0 0 16px -2px rgba(239, 68, 68, 0.35)`
- **Scanner Pulse Active**: `0 0 20px -4px rgba(56, 189, 248, 0.40)`
- **Subtle Surface Lift**: `0 4px 20px rgba(0, 0, 0, 0.45)` for floating panels.

## Shapes

The interface balances sharp industrial geometry with soft ergonomics (`roundedness: 1`):
- Standard cards, sheet containers, and status alerts use `0.5rem` (`rounded-lg`) corners to maintain an engineered, dashboard-grade profile.
- Action items, filter chips, and pill indicators scale down to `0.25rem` (`rounded`) for tight precision.
- Buttons and form fields strictly follow `0.25rem` corners. High-radius circular pills are reserved exclusively for numerical counter indicators and micro-badges.

## Components

### Buttons & Trigger Elements
- **Primary Action (Scan / Patch)**: Background `#38BDF8`, foreground `#090D16`, font `Geist` weight 600. On active state, scales down to `0.98` with a Cyan perimeter haze.
- **Secondary Action (Filter / Branch Select)**: Surface `#111827` at 80% opacity, border 1px solid `#1E293B`, text `#F8FAFC`.
- **Destructive Action (Revoke / Purge)**: Border 1px solid `#EF4444`, background `rgba(239, 68, 68, 0.10)`, text `#EF4444`.

### Vulnerability Badges & Chips
- Structure: 1px border enclosing tinted transparent backgrounds.
- Composition: Monospaced dot or textual code indicator + CVSS numeric score (`9.8`) + uppercase label (`CRITICAL`).
- **Pill Specs**:
  - `Critical`: Background `rgba(239, 68, 68, 0.12)`, Border `rgba(239, 68, 68, 0.40)`, Text `#F87171`.
  - `High`: Background `rgba(249, 115, 22, 0.12)`, Border `rgba(249, 115, 22, 0.40)`, Text `#FB923C`.
  - `Moderate`: Background `rgba(245, 158, 11, 0.12)`, Border `rgba(245, 158, 11, 0.40)`, Text `#FBBF24`.
  - `Safe`: Background `rgba(16, 185, 129, 0.12)`, Border `rgba(16, 185, 129, 0.40)`, Text `#34D399`.

### CVE & Dependency Cards
- Enclosed containers with a dark slate fill (`#111827`), divided into:
  1. **Header Row**: Monospaced package coordinate (e.g., `tar@6.1.11`) left-aligned; severity badge right-aligned.
  2. **Core Body**: Single-line CVE ID in Cyan (`CVE-2024-XXXX`), followed by clamped 2-line advisory copy in muted Inter (`#94A3B8`).
  3. **Metadata Footer**: Impacted path tree, fixed-in version badge (`Fix: 6.1.12`), and upstream exploit likelihood indicator.
- Left-edge status stripe: 2px wide vertical border aligned to the respective severity token color.

### Form Inputs & Query Terminals
- Search fields resemble command shells: `#090D16` inset background, 1px `#1E293B` stroke, leading glyph `$` or search prism, and trailing keyboard shortcut indicator (e.g., `⌘K`).
- Focus state activates a 1px border transition to `#38BDF8` with a subtle inner cyan sheen.

### Elevated Bottom Sheets
- Fixed anchoring with a pull indicator: `36px` wide, `4px` high bar in `#334155`.
- Contains granular drill-down matrices: dependency graphs, blast-radius trees, and raw JSON exploit payloads rendered in monospaced blocks with horizontal scroll.