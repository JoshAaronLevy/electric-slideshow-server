import 'dotenv/config';
import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import rateLimit from 'express-rate-limit';
import axios from 'axios';
import { z } from 'zod';

// Validate required environment variables on boot
const SPOTIFY_CLIENT_ID = process.env.SPOTIFY_CLIENT_ID;
const SPOTIFY_REDIRECT_URI = process.env.SPOTIFY_REDIRECT_URI;
const PORT = process.env.PORT || '8080';
const CORS_ORIGIN = process.env.CORS_ORIGIN;

if (!SPOTIFY_CLIENT_ID) {
  throw new Error('Missing required env var: SPOTIFY_CLIENT_ID');
}
if (!SPOTIFY_REDIRECT_URI) {
  throw new Error('Missing required env var: SPOTIFY_REDIRECT_URI');
}

const app = express();

// Trust Render proxy
app.set('trust proxy', 1);

// Security middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));

// Logging (only in development)
if (process.env.NODE_ENV !== 'production') {
  app.use(morgan('dev'));
}

// Parse CORS_ORIGIN into an array
const rawOrigins = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);

// Validate CORS configuration on boot
if (rawOrigins.length === 0) {
  console.warn('[SpotifyAuth] CORS_ORIGIN is empty - all origins with Origin header will be rejected');
  console.warn('[SpotifyAuth] This is okay for mobile apps (they don\'t send Origin), but web clients will fail');
} else {
  console.log('[SpotifyAuth] CORS allowed origins:', rawOrigins);
}

const corsOptions: cors.CorsOptions = {
  origin(origin, callback) {
    // Allow requests without Origin header (curl, Postman, server-to-server, mobile apps)
    if (!origin) return callback(null, true);
    if (rawOrigins.includes(origin)) return callback(null, true);
    
    // Log rejection for debugging
    console.warn('[SpotifyAuth] CORS rejection', {
      rejectedOrigin: origin,
      allowedOrigins: rawOrigins,
    });
    return callback(new Error(`Not allowed by CORS: ${origin}`));
  },
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Correlation-ID'],
  exposedHeaders: ['X-Correlation-ID'],
  credentials: false
};

app.use(cors(corsOptions));

// Body parsing
app.use(express.json());

// Correlation ID middleware - for request tracing
app.use((req: Request, res: Response, next: NextFunction) => {
  // Check for client-provided correlation ID, or generate one
  const correlationId = (req.headers['x-correlation-id'] as string) || 
                        `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
  
  // Attach to request object for use in handlers
  (req as any).correlationId = correlationId;
  
  // Return in response headers for client-side debugging
  res.setHeader('X-Correlation-ID', correlationId);
  
  next();
});

// CORS preflight logging
app.options('*', (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;
  console.log('[SpotifyAuth] CORS preflight request', {
    correlationId,
    path: req.path,
    origin: req.headers.origin,
    requestMethod: req.headers['access-control-request-method'],
    requestHeaders: req.headers['access-control-request-headers'],
    ip: req.ip,
  });
  
  // The actual CORS headers are set by the cors() middleware above
  // Log what will be sent back
  console.log('[SpotifyAuth] CORS preflight response', {
    correlationId,
    path: req.path,
    origin: req.headers.origin,
    allowOrigin: res.getHeader('Access-Control-Allow-Origin'),
    allowMethods: res.getHeader('Access-Control-Allow-Methods'),
    allowHeaders: res.getHeader('Access-Control-Allow-Headers'),
  });
  
  res.sendStatus(204);
});

// Rate limiting for auth endpoints
const authRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute per IP
  message: { error: 'too_many_requests', details: 'Rate limit exceeded. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req: Request, res: Response) => {
    const correlationId = (req as any).correlationId;
    console.warn('[SpotifyAuth] Rate limit exceeded', {
      correlationId,
      ip: req.ip,
      path: req.path,
      method: req.method,
      origin: req.headers.origin,
      userAgent: req.headers['user-agent'],
    });
    res.status(429).json({
      error: 'too_many_requests',
      details: 'Rate limit exceeded. Please try again later.',
    });
  },
});

// Required Spotify scopes for playback and device control
const SPOTIFY_SCOPES = [
  'user-read-playback-state',
  'user-modify-playback-state',
  'user-read-currently-playing',
  'playlist-read-private',
  'playlist-read-collaborative',
];

// Helper function to call Spotify token endpoint
async function spotifyToken(params: URLSearchParams): Promise<any> {
  const response = await axios.post(
    'https://accounts.spotify.com/api/token',
    params.toString(),
    {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    }
  );
  return response.data;
}

// Health check endpoint
app.get('/healthz', (_req: Request, res: Response) => {
  res.json({ ok: true });
});

// Zod schemas for request validation
const tokenRequestSchema = z.object({
  code: z.string().min(1, 'code is required'),
  code_verifier: z.string()
    .min(43, 'code_verifier must be at least 43 characters')
    .max(128, 'code_verifier must be at most 128 characters'),
});

const refreshRequestSchema = z.object({
  refresh_token: z.string().min(1, 'refresh_token is required'),
});

// Middleware to validate Authorization header and extract bearer token
function requireBearerToken(req: Request, res: Response, next: NextFunction) {
  const correlationId = (req as any).correlationId;
  const authHeader = req.headers.authorization;
  
  if (!authHeader) {
    console.warn('[SpotifyAPI] Missing Authorization header', {
      correlationId,
      path: req.path,
      method: req.method,
    });
    return res.status(401).json({
      error: 'unauthorized',
      details: 'Missing Authorization header. Expected: Authorization: Bearer <access_token>',
    });
  }
  
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    console.warn('[SpotifyAPI] Invalid Authorization header format', {
      correlationId,
      path: req.path,
      method: req.method,
      authHeaderPrefix: authHeader.substring(0, 20),
    });
    return res.status(401).json({
      error: 'unauthorized',
      details: 'Invalid Authorization header format. Expected: Authorization: Bearer <access_token>',
    });
  }
  
  const token = parts[1];
  if (!token || token.length < 10) {
    console.warn('[SpotifyAPI] Invalid or empty access token', {
      correlationId,
      path: req.path,
      method: req.method,
    });
    return res.status(401).json({
      error: 'unauthorized',
      details: 'Invalid or empty access token',
    });
  }
  
  // Attach token to request for use in handlers
  (req as any).accessToken = token;
  next();
}

// POST /auth/spotify/token - Exchange authorization code for tokens (PKCE)
// Also used to build the authorize URL for frontend
app.post('/auth/spotify/token', authRateLimiter, async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;
  
  try {
    const { code, code_verifier } = req.body;
    
    console.log('[SpotifyAuth] Token exchange request received', {
      correlationId,
      hasCode: !!code,
      codeLength: code?.length,
      codePreview: code ? `${code.substring(0, 6)}...${code.substring(code.length - 6)}` : undefined,
      hasCodeVerifier: !!code_verifier,
      verifierLength: code_verifier?.length,
      origin: req.headers.origin,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
    });
    
    // Validate request body
    const validationResult = tokenRequestSchema.safeParse(req.body);
    if (!validationResult.success) {
      console.log('[SpotifyAuth] Token exchange validation failed', {
        correlationId,
        errors: validationResult.error.errors.map(e => `${e.path.join('.')}: ${e.message}`),
      });
      return res.status(400).json({
        error: 'invalid_request',
        details: validationResult.error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ')
      });
    }

    console.log('[SpotifyAuth] Token exchange validation passed', { correlationId });

    const { code: validatedCode, code_verifier: validatedCodeVerifier } = validationResult.data;

    // Build Spotify token request params
    const params = new URLSearchParams({
      grant_type: 'authorization_code',
      code: validatedCode,
      redirect_uri: SPOTIFY_REDIRECT_URI,
      client_id: SPOTIFY_CLIENT_ID,
      code_verifier: validatedCodeVerifier,
      scope: SPOTIFY_SCOPES.join(' '),
    });

    console.log('[SpotifyAuth] Calling Spotify token API', {
      correlationId,
      grantType: 'authorization_code',
      redirectUri: SPOTIFY_REDIRECT_URI,
      clientId: `${SPOTIFY_CLIENT_ID.substring(0, 8)}...`,
    });

    // Exchange code for tokens
    const tokenData = await spotifyToken(params);

    console.log('[SpotifyAuth] Token exchange successful', {
      correlationId,
      hasAccessToken: !!tokenData.access_token,
      hasRefreshToken: !!tokenData.refresh_token,
      tokenType: tokenData.token_type,
      expiresIn: tokenData.expires_in,
      scope: tokenData.scope,
    });

    // Return token response
    res.json({
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      token_type: tokenData.token_type,
      expires_in: tokenData.expires_in,
      scope: tokenData.scope,
    });
  } catch (error: any) {
    console.error('[SpotifyAuth] Token exchange error', {
      correlationId,
      status: error.response?.status,
      statusText: error.response?.statusText,
      error: error.response?.data?.error,
      errorDescription: error.response?.data?.error_description,
      message: error.message,
      fullResponse: error.response?.data,
    });
    
    const status = error.response?.status || 500;
    const details = error.response?.data || { message: error.message };

    res.status(status).json({
      error: 'spotify_token_exchange_failed',
      details,
    });
  }
});

// POST /auth/spotify/refresh - Refresh access token
app.post('/auth/spotify/refresh', authRateLimiter, async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;
  
  try {
    const { refresh_token } = req.body;
    
    console.log('[SpotifyAuth] Token refresh request received', {
      correlationId,
      hasRefreshToken: !!refresh_token,
      tokenLength: refresh_token?.length,
      tokenPreview: refresh_token ? `${refresh_token.substring(0, 6)}...${refresh_token.substring(refresh_token.length - 6)}` : undefined,
      origin: req.headers.origin,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
    });
    
    // Validate request body
    const validationResult = refreshRequestSchema.safeParse(req.body);
    if (!validationResult.success) {
      console.log('[SpotifyAuth] Token refresh validation failed', {
        correlationId,
        errors: validationResult.error.errors.map(e => `${e.path.join('.')}: ${e.message}`),
      });
      return res.status(400).json({
        error: 'invalid_request',
        details: validationResult.error.errors.map(e => `${e.path.join('.')}: ${e.message}`).join(', ')
      });
    }

    console.log('[SpotifyAuth] Token refresh validation passed', { correlationId });

    const { refresh_token: validatedRefreshToken } = validationResult.data;

    // Build Spotify refresh request params
    const params = new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: validatedRefreshToken,
      client_id: SPOTIFY_CLIENT_ID,
      scope: SPOTIFY_SCOPES.join(' '),
    });

    console.log('[SpotifyAuth] Calling Spotify refresh API', {
      correlationId,
      grantType: 'refresh_token',
      clientId: `${SPOTIFY_CLIENT_ID.substring(0, 8)}...`,
    });

    // Refresh token
    const tokenData = await spotifyToken(params);

    console.log('[SpotifyAuth] Token refresh successful', {
      correlationId,
      hasAccessToken: !!tokenData.access_token,
      hasNewRefreshToken: !!tokenData.refresh_token,
      willPreserveOldRefreshToken: !tokenData.refresh_token,
      tokenType: tokenData.token_type,
      expiresIn: tokenData.expires_in,
      scope: tokenData.scope,
    });

    // Return token response (preserve old refresh_token if Spotify doesn't send a new one)
    res.json({
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token ?? validatedRefreshToken,
      token_type: tokenData.token_type,
      expires_in: tokenData.expires_in,
      scope: tokenData.scope,
    });
  } catch (error: any) {
    console.error('[SpotifyAuth] Token refresh error', {
      correlationId,
      status: error.response?.status,
      statusText: error.response?.statusText,
      error: error.response?.data?.error,
      errorDescription: error.response?.data?.error_description,
      message: error.message,
      fullResponse: error.response?.data,
    });
    
    const status = error.response?.status || 500;
    const details = error.response?.data || { message: error.message };

    res.status(status).json({
      error: 'spotify_refresh_failed',
      details,
    });
  }
});

// GET /api/spotify/me - Get current user's Spotify profile
app.get('/api/spotify/me', authRateLimiter, requireBearerToken, async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;
  const accessToken = (req as any).accessToken;
  try {
    const response = await axios.get('https://api.spotify.com/v1/me', {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    res.json({ ok: true, profile: response.data });
  } catch (error: any) {
    const status = error.response?.status || 500;
    let code = 'UNEXPECTED_ERROR';
    let message = 'Failed to fetch Spotify profile.';
    if (status === 401) {
      code = 'UNAUTHORIZED';
      message = 'Spotify token is invalid or expired.';
    }
    res.status(status).json({ ok: false, code, message, details: error.response?.data || { message: error.message } });
  }
});

// GET /api/spotify/playlists - Get current user's playlists
app.get('/api/spotify/playlists', authRateLimiter, requireBearerToken, async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;
  const accessToken = (req as any).accessToken;
  try {
    const limit = Math.min(parseInt(req.query.limit as string) || 50, 50);
    const offset = parseInt(req.query.offset as string) || 0;
    const response = await axios.get('https://api.spotify.com/v1/me/playlists', {
      headers: { 'Authorization': `Bearer ${accessToken}` },
      params: { limit, offset },
    });
    res.json({ ok: true, playlists: response.data });
  } catch (error: any) {
    const status = error.response?.status || 500;
    let code = 'UNEXPECTED_ERROR';
    let message = 'Failed to fetch Spotify playlists.';
    if (status === 401) {
      code = 'UNAUTHORIZED';
      message = 'Spotify token is invalid or expired.';
    }
    res.status(status).json({ ok: false, code, message, details: error.response?.data || { message: error.message } });
  }
});

// GET /api/spotify/devices - Get available Spotify devices
app.get('/api/spotify/devices', authRateLimiter, requireBearerToken, async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;
  const accessToken = (req as any).accessToken;
  
  console.log('[SpotifyAPI] Devices request received', {
    correlationId,
    path: req.path,
    method: req.method,
    origin: req.headers.origin,
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  });
  
  try {
    const response = await axios.get('https://api.spotify.com/v1/me/player/devices', {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    
    console.log('[SpotifyAPI] Devices request successful', {
      correlationId,
      status: response.status,
      deviceCount: response.data.devices?.length || 0,
    });
    
    // Return devices array, empty if no devices found
    res.json({ devices: response.data.devices || [] });
  } catch (error: any) {
    const status = error.response?.status || 500;
    const details = error.response?.data || { message: error.message };
    
    console.error('[SpotifyAPI] Devices request failed', {
      correlationId,
      status,
      statusText: error.response?.statusText,
      error: error.response?.data?.error,
      errorDescription: error.response?.data?.error_description,
      message: error.message,
      fullResponse: error.response?.data,
    });
    
    // Handle specific Spotify API error cases
    if (status === 401) {
      return res.status(401).json({
        error: 'unauthorized',
        details: 'Spotify token is invalid or expired.',
      });
    }
    
    if (status === 403) {
      return res.status(403).json({
        error: 'forbidden',
        details: 'Insufficient permissions to access Spotify devices.',
      });
    }
    
    if (status === 429) {
      return res.status(429).json({
        error: 'rate_limited',
        details: 'Spotify API rate limit exceeded. Please try again later.',
      });
    }
    
    // Generic error response for other cases
    res.status(status).json({
      error: 'spotify_api_error',
      details: details.error?.message || details.message || 'Failed to fetch Spotify devices.',
    });
  }
});

// PUT /api/spotify/playback/start/:playlistId - Start playback on available device
app.put('/api/spotify/playback/start/:playlistId', authRateLimiter, requireBearerToken, async (req: Request, res: Response) => {
  const correlationId = (req as any).correlationId;
  const accessToken = (req as any).accessToken;
  const { playlistId } = req.params;
  
  console.log('[SpotifyAPI] Start playback request received', {
    correlationId,
    path: req.path,
    method: req.method,
    playlistId,
    origin: req.headers.origin,
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  });
  
  try {
    // Step 1: Get available devices
    console.log('[SpotifyAPI] Fetching available devices', { correlationId });
    const devicesResponse = await axios.get('https://api.spotify.com/v1/me/player/devices', {
      headers: { 'Authorization': `Bearer ${accessToken}` },
    });
    
    const devices = devicesResponse.data.devices || [];
    console.log('[SpotifyAPI] Devices fetched successfully', {
      correlationId,
      deviceCount: devices.length,
      devices: devices.map((d: any) => ({
        id: d.id,
        name: d.name,
        type: d.type,
        is_active: d.is_active,
        is_restricted: d.is_restricted,
      })),
    });
    
    // Step 2: Handle NO_ACTIVE_DEVICE scenario
    if (devices.length === 0) {
      console.log('[SpotifyAPI] No devices found', { correlationId });
      return res.status(409).json({
        ok: false,
        code: 'NO_ACTIVE_DEVICE',
        message: 'No active Spotify devices. Please open Spotify on one of your devices and start playing something once, then try again.',
      });
    }
    
    // Step 3: Select target device using the specified strategy
    let targetDevice = null;
    
    // Prefer device with is_active === true
    const activeDevice = devices.find((d: any) => d.is_active === true);
    if (activeDevice) {
      targetDevice = activeDevice;
      console.log('[SpotifyAPI] Selected active device', {
        correlationId,
        deviceId: targetDevice.id,
        deviceName: targetDevice.name,
        deviceType: targetDevice.type,
      });
    } else {
      // Fall back to first device of type "Computer"
      const computerDevice = devices.find((d: any) => d.type === 'Computer');
      if (computerDevice) {
        targetDevice = computerDevice;
        console.log('[SpotifyAPI] Selected computer device (no active device found)', {
          correlationId,
          deviceId: targetDevice.id,
          deviceName: targetDevice.name,
          deviceType: targetDevice.type,
        });
      } else {
        // Use first device in array as final fallback
        targetDevice = devices[0];
        console.log('[SpotifyAPI] Selected first available device (no active or computer device found)', {
          correlationId,
          deviceId: targetDevice.id,
          deviceName: targetDevice.name,
          deviceType: targetDevice.type,
        });
      }
    }
    
    // Step 4: Start playback on selected device
    console.log('[SpotifyAPI] Starting playback on selected device', {
      correlationId,
      deviceId: targetDevice.id,
      playlistId,
      contextUri: `spotify:playlist:${playlistId}`,
    });
    
    const playResponse = await axios.put(
      `https://api.spotify.com/v1/me/player/play?device_id=${targetDevice.id}`,
      {
        context_uri: `spotify:playlist:${playlistId}`,
        position_ms: 0,
      },
      {
        headers: { 'Authorization': `Bearer ${accessToken}` },
      }
    );
    
    console.log('[SpotifyAPI] Playback started successfully', {
      correlationId,
      status: playResponse.status,
      deviceId: targetDevice.id,
      deviceName: targetDevice.name,
      playlistId,
    });
    
    // Step 5: Return success response
    res.json({
      ok: true,
      message: 'Playback started successfully',
      device: {
        id: targetDevice.id,
        name: targetDevice.name,
        type: targetDevice.type,
        is_active: targetDevice.is_active,
      },
      playlistId,
    });
    
  } catch (error: any) {
    const status = error.response?.status || 500;
    const details = error.response?.data || { message: error.message };
    
    console.error('[SpotifyAPI] Start playback failed', {
      correlationId,
      status,
      statusText: error.response?.statusText,
      error: error.response?.data?.error,
      errorDescription: error.response?.data?.error_description,
      message: error.message,
      fullResponse: error.response?.data,
    });
    
    // Handle specific Spotify API error cases
    if (status === 401) {
      return res.status(401).json({
        ok: false,
        code: 'UNAUTHORIZED',
        message: 'Spotify token is invalid or expired.',
        details,
      });
    }
    
    if (status === 403) {
      return res.status(403).json({
        ok: false,
        code: 'FORBIDDEN',
        message: 'Insufficient permissions to control playback.',
        details,
      });
    }
    
    if (status === 404) {
      return res.status(404).json({
        ok: false,
        code: 'DEVICE_NOT_FOUND',
        message: 'The selected device is no longer available.',
        details,
      });
    }
    
    if (status === 429) {
      return res.status(429).json({
        ok: false,
        code: 'RATE_LIMITED',
        message: 'Spotify API rate limit exceeded. Please try again later.',
        details,
      });
    }
    
    // Handle specific playback errors
    if (status === 404 && error.response?.data?.error?.reason === 'NO_ACTIVE_DEVICE') {
      return res.status(409).json({
        ok: false,
        code: 'NO_ACTIVE_DEVICE',
        message: 'No active Spotify devices. Please open Spotify on one of your devices and start playing something once, then try again.',
        details,
      });
    }
    
    // Generic error response for other cases
    res.status(status).json({
      ok: false,
      code: 'UNEXPECTED_ERROR',
      message: 'Failed to start playback.',
      details,
    });
  }
});

// 404 handler - must come before global error handler
app.use((req: Request, res: Response, _next: NextFunction) => {
  const correlationId = (req as any).correlationId;
  console.warn('[SpotifyAuth] 404 Not Found', {
    correlationId,
    method: req.method,
    path: req.path,
    url: req.url,
    origin: req.headers.origin,
    userAgent: req.headers['user-agent'],
    ip: req.ip,
  });
  res.status(404).json({
    error: 'not_found',
    details: `Route ${req.method} ${req.path} does not exist`,
  });
});

// Global error handler
app.use((error: Error, req: Request, res: Response, _next: NextFunction) => {
  const correlationId = (req as any).correlationId;
  console.error('[SpotifyAuth] Unhandled error', {
    correlationId,
    method: req.method,
    path: req.path,
    origin: req.headers.origin,
    error: error.message,
    stack: process.env.NODE_ENV !== 'production' ? error.stack : undefined,
  });
  res.status(500).json({
    error: 'internal_error',
    details: process.env.NODE_ENV !== 'production' ? error.message : 'An unexpected error occurred',
  });
});

// Start server
app.listen(parseInt(PORT, 10), () => {
  console.log(`🚀 Electric Slideshow Server running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🎵 Spotify Client ID: ${SPOTIFY_CLIENT_ID.substring(0, 8)}...`);
  console.log(`🔄 Redirect URI: ${SPOTIFY_REDIRECT_URI}`);
  console.log('[SpotifyAuth] Spotify OAuth configuration loaded', {
    clientId: `${SPOTIFY_CLIENT_ID.substring(0, 8)}...`,
    redirectUri: SPOTIFY_REDIRECT_URI,
    corsOrigin: CORS_ORIGIN || 'all origins (development mode)',
  });
});
