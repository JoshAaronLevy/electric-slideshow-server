You are helping debug the Spotify OAuth token exchange for *Electric Slideshow*, a macOS SwiftUI app.

The app successfully receives the Spotify redirect callback, but the token exchange fails on the Swift side with:

```
A server with the specified hostname could not be found.
Failed URL: https://electric-slideshow-server.onrender.com/auth/spotify/token
```

In the browser, loading the same URL returns:

```
{
  "error": "not_found",
  "details": "Route GET /auth/spotify/token does not exist"
}
```

This proves the server is reachable, so the issue may be:

* Incorrect/mismatched route on the backend
* Wrong HTTP verb (Swift may be calling POST, server only defines GET or vice versa)
* Missing `/auth` prefix due to router nesting
* Deprecated path from the old “slideshow-buddy-server” repo
* Render environment variables using the old redirect URI or app name
* PKCE token endpoint incorrectly copied during repo migration

### **What I need you to check**

1. Search the entire backend for where the token exchange route is defined.
   It should be a POST route:

   ```
   POST /auth/spotify/token
   ```

2. Verify the actual effective route path, considering:

   * Router prefixing (`app.use('/auth', router)`)
   * Any middleware that modifies base paths

3. Ensure the handler for the token exchange:

   * Reads `code`, `code_verifier`, and `redirect_uri` correctly
   * Does NOT validate redirect URI against old values from slideshow-buddy
   * Uses the correct Spotify app credentials

4. Check all Render environment variables:

   * `SPOTIFY_CLIENT_ID`
   * `SPOTIFY_CLIENT_SECRET`
   * `SPOTIFY_REDIRECT_URI`
     Should match: `com.electricslideshow://callback` (or the exact updated value)
   * Ensure no old `slideshow-buddy` values remain

5. Confirm the backend doesn’t expect a route like:

   * `/api/auth/spotify/token`
   * `/spotify/token`
   * `/auth/token`
   * `/oauth/token`

If the actual backend route does NOT match the expected endpoint `/auth/spotify/token`, please update the code so that the correct POST route exists and is wired up.

When you're done, explain what you found and what fixes (if any) you applied.