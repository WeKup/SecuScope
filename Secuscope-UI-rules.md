# SecuScope UI Rules

## Scope

These rules apply to current and future SecuScope UI work.

The current application is a Flask/Jinja app using Tailwind through CDN and
Chart.js in templates. Shadcn UI, Motion and GSAP require a JavaScript frontend
toolchain. Do not create a new Next.js, Vite or React project inside this
repository unless the migration is explicitly requested.

When a React/TypeScript frontend exists, the rules below are mandatory.

## Mandatory Visual Stack

- Structural and graphic components must use Shadcn UI primitives: Table, Card,
  Badge, Dialog and Chart.
- Do not hand-roll duplicate React components when a Shadcn primitive exists.
- List entrances, chart reveals, panel openings and view transitions must use Motion.
- The real-time cyber scan loader is the only place where GSAP is allowed and expected.
- Do not add one-off CSS files or custom Tailwind systems outside the app theme.
  Extend the design system instead.

## Current Flask/Jinja Exception

- Until the React/TypeScript frontend migration exists, keep Flask templates
  compatible with the current Tailwind CDN setup.
- Reuse the existing slate/blue/emerald/red/yellow palette and dashboard density.
- Use Chart.js only for existing Jinja dashboards where no React renderer exists.
- Keep JavaScript progressive and local to the template when it only enhances an
  already-rendered audit page.
- Do not change backend scan, scoring or persistence behavior for UI-only work.

## UX/UI Philosophy

- Validate information hierarchy before coding: critical findings and score impact
  come first, details second, decorative content last.
- Avoid AI design cliches: no gratuitous purple neon gradients, glowing blobs,
  fake holograms or ornamental cyberpunk effects.
- The product should read as an enterprise cybersecurity dashboard: restrained,
  dense, scannable, precise.
- Support dark mode first and preserve compatibility with the existing light/dark
  theme direction.
- Use color to encode status and severity, not decoration.
- Prefer compact cards, tables, badges and charts that help compare risk quickly.

## Theme Inheritance

- Components must inherit global colors, spacing, radius and Tailwind conventions
  already present in Part 1.
- Use `slate` for surfaces, `blue` for neutral security telemetry, `emerald` for
  positive states, `yellow/orange` for warnings and `red` for critical risk.
- Keep typography compact inside dashboards.
- Avoid nested cards and decorative section wrappers.