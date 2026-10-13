# Dashboard development

Next.js App Router, TypeScript strict mode, Tailwind CSS, Lucide and shadcn/ui button primitive. API bridge forwards an explicit in-memory bearer token to an operator configured fixed FastAPI origin. Routes and body sizes are allowlisted, redirects denied, timeout bounded, cache disabled. Tokens are never in browser storage, cookies or URLs. Disconnect clears identity and data; aborted effects avoid old-session responses.

```powershell
cd frontend
npm ci
npm run dev
npm run lint
npm run typecheck
npm test
npm run build
npx playwright install chromium
npm run test:e2e
```

Start backend and worker separately for interactive use; E2E owns loopback test API/worker/frontend servers. Configure `REPOGUARD_API_URL` on the Next.js server for deployment, never in public client env. GitHub App connection requires a provisioned installation; fixtures are visibly local. Empty, loading, failure, authorization, cancellation, findings, category/rule coverage and history are driven by real API data. Proposal/approval controls arrive with G08/G09.

References: [Next.js installation](https://nextjs.org/docs/app/getting-started/installation), [Tailwind setup](https://tailwindcss.com/docs/installation/framework-guides/nextjs), [shadcn manual setup](https://ui.shadcn.com/docs/installation/manual).
