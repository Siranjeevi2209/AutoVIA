# Auto-VIA — Automotive Vulnerability Intelligence Aggregator

**Open-Source Platform for Automotive Cybersecurity Vulnerability Intelligence**
ISO/SAE 21434 & UNECE WP.29 R155 Aligned | CVSS v4.0 | ARS Hybrid Scoring

---

## Quick Start (Local Development)

```bash
# 1. Install dependencies
npm install

# 2. Start dev server
npm run dev

# 3. Open in browser
#    → http://localhost:5173
```

---

## Deploy to Vercel (Recommended — Fastest)

### Option A: Deploy via Vercel CLI

```bash
# 1. Install Vercel CLI
npm install -g vercel

# 2. From the project root, run:
vercel

# 3. Follow the prompts:
#    - Link to existing project? → No
#    - Project name? → autovia
#    - Framework? → Vite (auto-detected)
#    - Build command? → (leave default: vite build)
#    - Output directory? → (leave default: dist)

# 4. Deploy to production:
vercel --prod
```

Your site will be live at `https://autovia.vercel.app` (or your custom domain).

### Option B: Deploy via GitHub + Vercel Dashboard

1. Push this project to a GitHub repository
2. Go to [vercel.com](https://vercel.com) → Sign in with GitHub
3. Click **"Add New Project"**
4. Import your `autovia` repository
5. Vercel auto-detects Vite — click **Deploy**
6. Done. Every push to `main` auto-deploys.

---

## Deploy to Netlify

### Option A: Netlify CLI

```bash
# 1. Install Netlify CLI
npm install -g netlify-cli

# 2. Build the project
npm run build

# 3. Deploy
netlify deploy --prod --dir=dist
```

### Option B: Netlify Dashboard (Drag & Drop)

1. Run `npm run build` locally
2. Go to [app.netlify.com](https://app.netlify.com)
3. Drag the `dist/` folder onto the deploy zone
4. Instant live URL

### Option C: GitHub + Netlify

1. Push to GitHub
2. Go to Netlify → **"Add new site"** → **"Import from Git"**
3. Select your repo
4. Build command: `npm run build`
5. Publish directory: `dist`
6. Click **Deploy site**

---

## Deploy to GitHub Pages (Free)

```bash
# 1. Add base path to vite.config.js (replace 'autovia' with your repo name):
#    base: '/autovia/',

# 2. Install gh-pages
npm install -D gh-pages

# 3. Add deploy script to package.json:
#    "deploy": "npm run build && gh-pages -d dist"

# 4. Run deploy
npm run deploy
```

Then enable GitHub Pages in your repo settings → Source: `gh-pages` branch.

---

## Deploy to Cloudflare Pages

1. Push to GitHub
2. Go to [dash.cloudflare.com](https://dash.cloudflare.com) → Pages
3. Connect your GitHub repo
4. Build settings:
   - Framework: Vite
   - Build command: `npm run build`
   - Build output: `dist`
5. Deploy

---

## Deploy to a VPS / Self-Hosted (Docker)

```dockerfile
# Dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

```bash
# Build and run
docker build -t autovia .
docker run -p 8080:80 autovia

# Access at http://localhost:8080
```

---

## Project Structure

```
autovia/
├── index.html              # Entry HTML
├── package.json            # Dependencies & scripts
├── vite.config.js          # Vite configuration
├── public/
│   └── favicon.svg         # Auto-VIA favicon
└── src/
    ├── main.jsx            # React mount point
    └── AutoVIA.jsx         # Full Auto-VIA platform component
```

---

## Architecture Implemented

- **ARS Computation Engine** — `Base × ASIL_mod × Reach_mod × Exploit_mod` (capped at 10.0)
- **10-Domain ECU Taxonomy** — Braking, Steering, Powertrain, Chassis, ADAS, Gateway, Telematics, Infotainment, Body, Diagnostics
- **Priority Tiers** — P0 Critical → P3 Low with treatment SLAs
- **AVR Schema v3.0** — Six field groups (A–F) per specification
- **TARA Export** — ISO/SAE 21434 Cl.9 asset register entries
- **KEV Override** — CISA KEV listing forces P0_critical
- **Justification Trace** — Full audit trail for every ARS computation

---

## Standards Alignment

| Standard | Coverage |
|----------|----------|
| ISO/SAE 21434 Cl.15 | Vulnerability management, TARA export |
| UNECE WP.29 R155 | Continuous monitoring, CSMS evidence |
| CVSS v4.0 | Base + Threat metric scoring |
| STIX 2.1 | Structured output format |
| NHTSA Guidance | ASIL-weighted safety scoring |

---

**Designed & Architected by Siranjeevi Srinivasa Raghavan**
Automotive Cybersecurity Systems Engineer — Auto-VIA Framework
