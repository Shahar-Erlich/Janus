# Janus UI

React + TypeScript frontend scaffold for the Janus monitoring dashboard shown in your Stitch mockups.

## Included

- Overview dashboard
- Live traffic monitoring screen
- Reusable layout and card components
- Recharts graphs
- Mock data layer ready to replace with API calls
- Placeholder routes for the rest of the SOC/admin screens

## Stack

- React
- TypeScript
- Vite
- React Router
- Recharts
- Lucide React

## Run

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

## Suggested next integration steps

1. Replace `src/data/mockData.ts` with calls to your Janus backend.
2. Feed live packet rows from WebSocket / SSE.
3. Map protobuf-decoded events to the `PacketRecord` and overview KPI models.
4. Connect rules, users, and engine toggles to real API routes.

## Structure

```text
src/
  components/
    live-traffic/
    overview/
  data/
  layout/
  pages/
  styles/
  types/
  utils/
```
