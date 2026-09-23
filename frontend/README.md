# ORACLE Frontend

This frontend powers the ORACLE operations console for missions, findings, graph exploration, reports, and AI copilot workflows.

## Development

Install dependencies and start the local app:

```bash
npm install
npm run dev
```

The app will be available at http://localhost:3000.

## Environment

The frontend expects the backend API at the address exposed through the `NEXT_PUBLIC_API_URL` environment variable. If it is unset, it defaults to http://localhost:8000/api.

## Verification

Before shipping UI changes, verify the app builds successfully:

```bash
npm run build
```
