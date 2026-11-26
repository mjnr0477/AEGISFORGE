---
version: alpha
name: "AegisForge"
description: "A local security workbench for inspecting software, proving findings, and verifying repairs."
colors:
  primary: "#171B1D"
  background: "#101416"
  surface: "#1A2023"
  elevated: "#232B2F"
  text: "#EDF1EF"
  muted: "#9AA7A3"
  line: "#344044"
  accent: "#E5A43B"
  critical: "#E7685B"
  success: "#70B58B"
typography:
  sans:
    fontFamily: "Inter, ui-sans-serif, system-ui, sans-serif"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Consolas, monospace"
rounded:
  sm: "0.375rem"
  md: "0.625rem"
  lg: "1rem"
  xl: "1.375rem"
spacing:
  section-gap: "2rem"
  page-max: "76rem"
components:
  button: {}
  card: {}
  upload-zone: {}
  finding: {}
---
# AegisForge Design System

## Overview

### Creative North Star

AegisForge should feel like an engineer's field instrument: a portable security workbench, not a chatbot, marketing site, or generic cloud dashboard. Its language is evidence, scope, rules, file locations, verification, and repair.

### Product context and register

- **Audience and primary job:** Independent developers and small teams inspecting projects they own or are authorized to assess.
- **Target market(s) and evidence:** Global developer tooling; phone-first local workflow is prioritized because the project owner develops from Android.
- **Locale(s) and language policy:** English first; system font fallback supports user-installed scripts.
- **Usage scene:** Local browser on a phone or laptop with an uploaded project archive; offline-capable after package installation.
- **Register:** Product interface.
- **Memorable signature:** A narrow amber "instrument rail" that marks scan state, scope, and finding severity.
- **Restraint:** Evidence and code snippets remain readable; avoid decorative graphs, chatbot bubbles, glossy gradients, and oversized empty hero space.
- **Anti-references:** Generic AI chat screens, neon hacker tropes, and cloud dashboards that imply remote processing.
- **Token ownership/runtime mapping:** This file owns the visual intent. The web UI uses matching CSS custom properties in `aegisforge/web/app.css`; update both in the same change when a durable token changes.

## Colors

The interface uses charcoal surfaces and restrained amber for focus, scope and action. Severity colors are semantic and always paired with text labels. Surfaces are distinguished by fine rules and small tonal changes rather than heavy shadows. Keep text and code snippets at high contrast.

## Typography

System sans is used for headings, labels and explanations; monospace is reserved for file paths, rule IDs, line numbers and evidence. Keep body copy compact but readable on narrow phones. Use tabular numerals for counts.

## Layout

A maximum-width workbench uses a two-column desktop arrangement that collapses to one column on phone widths. The upload surface and scan action remain prominent. Findings use a single-column reading order and wrap long paths and evidence.

## Elevation & Depth

Use borders and surface contrast, not floating cards or heavy shadows. The result panel can use a slightly elevated background to separate operational content.

## Shapes

Controls use modest radii. The upload target uses a dashed perimeter that changes on focus and drag-over. Finding cards use a solid hairline border and a slim semantic severity rail.

## Components

### Foundational visual states

Interactive items define default, hover, focus-visible, active, disabled and busy states. Reduced-motion mode removes nonessential transitions.

### Buttons and actions

One primary action, "Run local scan". Secondary actions remain outline or text buttons. The export action appears only after results exist. Cancel is visible while the request is running.

### Navigation and data display

The interface has a compact product header and one main work area. Finding lists are text-first, with filter buttons for severity and no-results states for empty filters.

### Forms and overlays

The ZIP picker is a real file input with a keyboard-operable drop target. Validation appears inline. No browser alerts, prompts or confirmation dialogs are used.

### Iconography

Use inline simple geometric SVG where needed; do not depend on third-party icon fonts or remote assets.

### Motion

Use short state transitions only; respect `prefers-reduced-motion`. No ambient or decorative animation.

### Content and data visualization

Use exact words: local, scan, finding, evidence, remediation, baseline, repair. Never imply a clean scan proves security. All result content is rendered as text, not interpreted HTML.

## Do's and Don'ts

- **Do:** Make local processing and the selected archive scope obvious.
- **Do:** Show every finding with rule ID, severity, path, line and redacted evidence.
- **Don't:** Imply the server contacts a remote AI or uploads project code.
- **Don't:** render scan output as HTML or execute uploaded files.
