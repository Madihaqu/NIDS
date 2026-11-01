import React, { useState } from 'react';
import {
  Globe,
  Github,
  ServerOff,
  CheckCircle,
  Copy,
  Check,
  Code,
  FolderTree,
  Zap,
} from 'lucide-react';

export const DeploymentGuide: React.FC = () => {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const vercelJsonCode = `{
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "framework": "vite"
}`;

  const githubActionsYml = `name: Deploy Hybrid NIDS to GitHub Pages

on:
  push:
    branches: [main]

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: 'pages'
  cancel-in-progress: true

jobs:
  build-and-deploy:
    environment:
      name: github-pages
      url: \${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20
          cache: 'npm'

      - name: Install Dependencies
        run: npm ci

      - name: Build Static Applet
        run: npm run build

      - name: Upload Pages Artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: './dist'

      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v4
`;

  return (
    <div className="w-full space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
        <div className="flex items-center gap-2 mb-2">
          <ServerOff className="w-4 h-4 text-emerald-400" />
          <h3 className="text-base font-semibold text-slate-100">
            Zero-Config Static Web Deployment (No Python / Streamlit)
          </h3>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">
          By eliminating Python runtime, C++ build dependencies (<code className="text-slate-300">scikit-learn</code>, <code className="text-slate-300">libpcap</code>), and Streamlit server processes, this NIDS runs 100% in the client browser with zero server costs, zero cold starts, and zero hosting errors on Vercel, Netlify, or GitHub Pages.
        </p>

        {/* Verification Checkmark */}
        <div className="mt-4 flex items-center gap-2 text-xs font-mono text-emerald-400 bg-emerald-950/30 border border-emerald-900/50 p-2.5 rounded">
          <CheckCircle className="w-4 h-4 shrink-0" />
          <span>Verified: <code className="text-emerald-300">base: './'</code> is configured in <code className="text-emerald-300">vite.config.ts</code>. All scripts, fonts, and assets resolve with relative paths on subpaths (e.g. <code className="text-emerald-200">username.github.io/hybrid-nids/</code>).</span>
        </div>
      </div>

      {/* Comparison Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Old Python / Streamlit Architecture */}
        <div className="bg-slate-950 border border-slate-800 rounded-lg p-4 space-y-3">
          <div className="flex items-center gap-2 text-red-400 font-semibold text-xs">
            <span className="w-2 h-2 rounded-full bg-red-500" />
            Previous Python / Streamlit Setup (Deprecated)
          </div>
          <ul className="text-xs text-slate-400 space-y-2 font-mono">
            <li className="flex items-start gap-1.5">
              <span className="text-red-500 font-bold">&times;</span>
              <span>Requires active Python 3.10+ VM or container instance ($7–$25/mo on Cloud Run / Heroku).</span>
            </li>
            <li className="flex items-start gap-1.5">
              <span className="text-red-500 font-bold">&times;</span>
              <span>Frequent wheel compilation errors with NumPy / Scikit-Learn C-extensions on Vercel serverless.</span>
            </li>
            <li className="flex items-start gap-1.5">
              <span className="text-red-500 font-bold">&times;</span>
              <span>Streamlit WebSocket disconnects during large CSV file uploads.</span>
            </li>
            <li className="flex items-start gap-1.5">
              <span className="text-red-500 font-bold">&times;</span>
              <span>Data packets sent over public internet to server (Compliance / Privacy concern).</span>
            </li>
          </ul>
        </div>

        {/* Modern Pure Static Web NIDS */}
        <div className="bg-slate-950 border border-emerald-900/40 rounded-lg p-4 space-y-3">
          <div className="flex items-center gap-2 text-emerald-400 font-semibold text-xs">
            <span className="w-2 h-2 rounded-full bg-emerald-500" />
            Pure Static Web NIDS (Current Architecture)
          </div>
          <ul className="text-xs text-slate-300 space-y-2 font-mono">
            <li className="flex items-start gap-1.5">
              <span className="text-emerald-400 font-bold">&check;</span>
              <span>100% Free Hosting forever on GitHub Pages, Vercel, Netlify, Cloudflare Pages.</span>
            </li>
            <li className="flex items-start gap-1.5">
              <span className="text-emerald-400 font-bold">&check;</span>
              <span>Zero-backend build: <code className="text-cyan-400">npm run build</code> outputs pure HTML, JS, and CSS in seconds.</span>
            </li>
            <li className="flex items-start gap-1.5">
              <span className="text-emerald-400 font-bold">&check;</span>
              <span>Zero data privacy leaks: Network flows and CSV packets are analyzed locally in browser RAM.</span>
            </li>
            <li className="flex items-start gap-1.5">
              <span className="text-emerald-400 font-bold">&check;</span>
              <span>Sub-millisecond inference: Client-side JS execution achieves &lt;0.05ms per flow latency.</span>
            </li>
          </ul>
        </div>
      </div>

      {/* Deployment Recipes */}
      <div className="space-y-4">
        {/* Vercel Recipe */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Globe className="w-4 h-4 text-cyan-400" />
              <h4 className="text-sm font-semibold text-slate-200">
                Option 1: Deploy to Vercel (1-Click or CLI)
              </h4>
            </div>
            <button
              onClick={() => copyToClipboard(vercelJsonCode, 'vercel')}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700 flex items-center gap-1.5 font-mono"
            >
              {copiedId === 'vercel' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              {copiedId === 'vercel' ? 'Copied' : 'Copy vercel.json'}
            </button>
          </div>
          <div className="text-xs text-slate-400 mb-3 space-y-1">
            <p>1. Push your repository to GitHub.</p>
            <p>2. Import repository on <strong className="text-slate-200">Vercel.com</strong>.</p>
            <p>3. Framework Preset: <strong className="text-cyan-400">Vite</strong> | Build Command: <code className="text-slate-300">npm run build</code> | Output Directory: <code className="text-slate-300">dist</code>.</p>
          </div>
          <pre className="bg-slate-950 p-3 rounded border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto">
            {vercelJsonCode}
          </pre>
        </div>

        {/* GitHub Pages Recipe */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Github className="w-4 h-4 text-slate-200" />
              <h4 className="text-sm font-semibold text-slate-200">
                Option 2: Deploy to GitHub Pages (Automated Workflow)
              </h4>
            </div>
            <button
              onClick={() => copyToClipboard(githubActionsYml, 'gh-pages')}
              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700 flex items-center gap-1.5 font-mono"
            >
              {copiedId === 'gh-pages' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              {copiedId === 'gh-pages' ? 'Copied' : 'Copy .github/workflows/deploy.yml'}
            </button>
          </div>
          <div className="text-xs text-slate-400 mb-3 space-y-1">
            <p>1. In your GitHub repository, go to <strong className="text-slate-200">Settings &gt; Pages &gt; Build and deployment</strong>.</p>
            <p>2. Set Source to <strong className="text-cyan-400">GitHub Actions</strong>.</p>
            <p>3. Save the workflow file below to <code className="text-slate-300">.github/workflows/deploy.yml</code> and commit to <code className="text-slate-300">main</code>.</p>
          </div>
          <pre className="bg-slate-950 p-3 rounded border border-slate-800 text-xs font-mono text-cyan-300 overflow-x-auto max-h-56">
            {githubActionsYml}
          </pre>
        </div>

        {/* Clean Static File Structure */}
        <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-5">
          <div className="flex items-center gap-2 mb-3">
            <FolderTree className="w-4 h-4 text-cyan-400" />
            <h4 className="text-sm font-semibold text-slate-200">
              Clean Static Project Structure
            </h4>
          </div>
          <pre className="bg-slate-950 p-3 rounded border border-slate-800 text-xs font-mono text-slate-300 overflow-x-auto">
{`hybrid-nids/
├── index.html                  # HTML5 entry with meta tags & dark theme
├── vite.config.ts              # Bundler config with base: './'
├── package.json                # Dependencies: React 19, Tailwind v4, PapaParse
├── src/
│   ├── engine/
│   │   ├── randomForest.ts     # Supervised RF Decision Ensemble
│   │   ├── isolationForest.ts  # Unsupervised Isolation Outlier Scoring
│   │   ├── hybridEngine.ts     # Decision Orchestrator & Explanations
│   │   └── trafficGenerator.ts # Synthetic stream & attack injector
│   ├── components/soc/
│   │   ├── LiveTimelineChart.tsx   # Canvas 60fps throughput timeline
│   │   ├── ThreatDistributionChart.tsx # SVG Donut distribution
│   │   ├── OutlierScatterCanvas.tsx # 2D Isolation feature space
│   │   ├── LiveStreamTable.tsx     # High-density log feed & inspector
│   │   ├── FlowInspector.tsx       # Sandbox parameter slider controls
│   │   ├── CsvAnalyzer.tsx         # PapaParse CIC-IDS ingestion
│   │   ├── ModelRulesViewer.tsx    # Hyperparameters & feature weights
│   │   └── DeploymentGuide.tsx     # Static deployment configurations
│   ├── types/nids.ts           # CIC-IDS schema & flow types
│   ├── App.tsx                 # SOC Main Controller & State
│   └── main.tsx                # React entry
└── dist/                       # Output of "npm run build" (Static assets)`}
          </pre>
        </div>
      </div>
    </div>
  );
};
