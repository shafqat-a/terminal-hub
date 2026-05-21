# terminal-hub e2e

Playwright tests for clipboard / paste behavior (spec §8.5).

## Setup

    cd e2e
    npm install
    npx playwright install chromium

## Run

    TH_BASE_URL=https://localhost:5999 npm test

The current tests assume the server is running and a primary user is already
signed in (cookie present). Auth fixture wiring is a fast follow.
