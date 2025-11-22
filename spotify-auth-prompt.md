You are helping debug Spotify OAuth + Web API integration for the macOS app Electric Slideshow.

### Context

- Front-end: macOS SwiftUI app (Electric Slideshow).
- Backend: Node/Express app hosted on Render (this repo).
- Spotify OAuth PKCE is handled by this backend. The macOS app calls this backend to:
  - Exchange `code` for tokens.
  - Fetch user profile.
  - Fetch Spotify library / playlists.

Current behavior:

- The user initiates “Connect to Spotify” from the app.
- Spotify consent page appears in the browser, user clicks “Agree”.
- The app receives the callback via custom URL and shows “Connected to Spotify”.
- In the Spotify account page on the web, **Electric Slideshow** appears under connected apps.

However:

- When the app tries to create a new slideshow playlist from the user’s Spotify account/library, the modal shows: **“Failed to load Spotify Library”**.
- When the app opens the profile modal (user icon), it shows: **“Failed to Load Profile”**.
- These calls likely go through backend endpoints such as:
  - Something like `/auth/spotify/token` for token exchange.
  - Something like `/spotify/me` or `/api/spotify/profile` for profile.
  - Something like `/spotify/playlists` or `/api/spotify/library` for the library/playlists.

Thus, OAuth appears to succeed superficially, but the subsequent backend API calls are failing.

### What I need you to do in this Node repo

1. Locate and inspect the route that handles the **code → token exchange**:
   - Likely something like:
     - `POST /auth/spotify/token`
     - Or a similar route in an auth router.
   - Check:
     - Does it use the new Spotify app credentials (client ID, secret, redirect URI)?
     - Is it using the correct `redirect_uri` (matching `com.electricslideshow://callback` or whichever is intended)?
     - Are you properly sending `code_verifier` if using PKCE?
     - What do you return to the client (Swift app) on success/failure?

2. Locate the routes used for:
   - Getting the **user profile** (the one that should back the “Load Profile” modal).
   - Getting the **Spotify library / playlists** (used by the “Failed to load Spotify Library” modal).

   These might be:
   - `GET /spotify/me`
   - `GET /spotify/profile`
   - `GET /spotify/playlists`
   - Or under `/api/spotify/...`

3. For each of these routes:
   - Confirm how the backend obtains the access/refresh token:
     - Is it expecting the Swift app to send tokens in headers/body?
     - Or is it using some server-side token/session store keyed by user?
   - Confirm that it is using the **new** Spotify client/app, not leftover config from the old “slideshow-buddy” backend.
   - Make sure the scopes requested at auth time are sufficient for:
     - Reading user profile (e.g. `user-read-email`, `user-read-private`)
     - Reading playlists/library (`playlist-read-private`, maybe `user-library-read`, etc.)

4. Improve logging and error handling:
   - In the token exchange route, profile route, and library/playlist route:
     - Log the full HTTP status and body of Spotify’s response if the call fails.
     - Return an informative error payload to the Swift app (HTTP status + a JSON message) so the front-end can surface more than just “Failed to load …”.
   - Make sure that if token exchange fails, the backend does NOT act as if everything is fine (and that the Swift app can detect this).

5. Fix any of the following if found:
   - Mismatched or incorrect redirect URI compared to what the Swift app and Spotify Developer Dashboard use.
   - Wrong paths being hit internally (e.g. calling an old “slideshow-buddy” path, or hitting `/me` with no Authorization header).
   - Using an outdated environment variable or Spotify client credentials that no longer match the new app.

Make minimal, focused changes. Do NOT refactor the architecture.  

When you’re done, summarize:
- What was misconfigured or broken in the token exchange or in the profile/library routes.
- What code or config you changed to fix it.