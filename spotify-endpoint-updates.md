# Backend Implementation Guide: Spotify Devices API Proxy

## Overview

This guide provides comprehensive implementation instructions for creating a backend proxy endpoint for Spotify's devices API. The current frontend implementation is making direct calls to Spotify's API, which needs to be redirected through the backend to resolve authentication scope issues and provide proper error handling.

## **Critical Issues Identified**

### 1. Frontend-Backend Mismatch
- **Current Issue**: Frontend calls `https://api.spotify.com/v1/me/player/devices` directly
- **Required Fix**: Frontend should call `/api/spotify/devices` (backend proxy)
- **Impact**: Direct API calls bypass backend authentication validation and scope management

### 2. Authentication Scope Error
- **Current Issue**: Token refresh fails with "invalid_scope" error
- **Root Cause**: Backend scope validation mismatches with frontend scopes
- **Required Scopes**: `user-read-playback-state`, `user-modify-playback-state`

### 3. Missing Backend Proxy Logic
- **Current Issue**: No backend endpoint exists for device management
- **Required**: Implement `/api/spotify/devices` proxy endpoint

## **Implementation Requirements**

### 1. API Endpoint Implementation

#### **Endpoint**: `GET /api/spotify/devices`

**Purpose**: Proxy requests to Spotify's `/v1/me/player/devices` endpoint with proper authentication and error handling.

**Request Headers**:
```
Authorization: Bearer <backend_access_token>
```

**Response Format**:
```json
{
  "devices": [
    {
      "id": "string",
      "name": "string", 
      "type": "string",
      "is_active": boolean,
      "is_restricted": boolean,
      "volume_percent": number,
      "is_private_session": boolean,
      "is_group": boolean
    }
  ]
}
```

**Error Response Format**:
```json
{
  "error": {
    "status": number,
    "message": "string",
    "reason": "string"
  }
}
```

### 2. Authentication & Scope Handling

#### **Scope Validation**
The backend must validate that tokens have the required scopes:
- `user-read-playback-state` - Required for reading device information
- `user-modify-playback-state` - Required for controlling playback

#### **Token Refresh Scope Fix**
The "invalid_scope" error occurs when the backend's scope validation doesn't match the scopes requested during token refresh. Ensure:

1. **Consistent Scopes**: Backend refresh endpoint uses the same scopes as initial authorization
2. **Scope Preservation**: Refresh tokens maintain original scopes
3. **Validation Logic**: Update scope validation to accept the required playback scopes

#### **Frontend Scopes** (for reference):
```javascript
[
  "playlist-read-private",
  "playlist-read-collaborative", 
  "user-library-read",
  "user-read-playback-state",
  "user-modify-playback-state"
]
```

### 3. Error Handling

#### **Authentication Failures**
- **401 Unauthorized**: Return structured error with refresh token guidance
- **403 Forbidden**: Return scope validation error
- **Token Expired**: Trigger automatic token refresh

#### **Spotify API Error Forwarding**
- Forward Spotify API errors with proper HTTP status codes
- Include original error messages for debugging
- Add backend correlation IDs for request tracking

#### **Network Issues**
- Implement retry logic for transient failures
- Set appropriate timeouts (30 seconds recommended)
- Handle DNS resolution failures gracefully

### 4. Response Format Standardization

#### **Success Response** (200 OK):
```json
{
  "success": true,
  "data": {
    "devices": [...]
  },
  "timestamp": "2025-11-24T22:19:02.232Z"
}
```

#### **Error Response** (4xx/5xx):
```json
{
  "success": false,
  "error": {
    "code": "DEVICE_FETCH_FAILED",
    "message": "Failed to fetch Spotify devices",
    "details": "Original Spotify error message",
    "status": 400
  },
  "timestamp": "2025-11-24T22:19:02.232Z"
}
```

## **Technical Implementation Details**

### **Backend Code Structure** (Node.js/Express Example)

```javascript
// routes/spotifyDevices.js
const express = require('express');
const router = express.Router();
const axios = require('axios');

// GET /api/spotify/devices
router.get('/devices', authenticateToken, validateScopes, async (req, res) => {
  try {
    // Extract user access token from request
    const accessToken = req.user.accessToken;
    
    // Validate required scopes
    const requiredScopes = ['user-read-playback-state', 'user-modify-playback-state'];
    const userScopes = req.user.scopes || [];
    
    const hasRequiredScopes = requiredScopes.every(scope => 
      userScopes.includes(scope)
    );
    
    if (!hasRequiredScopes) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'INSUFFICIENT_SCOPES',
          message: 'Missing required scopes for device access',
          required: requiredScopes,
          available: userScopes
        }
      });
    }
    
    // Make request to Spotify API
    const spotifyResponse = await axios.get(
      'https://api.spotify.com/v1/me/player/devices',
      {
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          'Content-Type': 'application/json'
        },
        timeout: 30000 // 30 second timeout
      }
    );
    
    // Return standardized response
    res.json({
      success: true,
      data: {
        devices: spotifyResponse.data.devices || []
      },
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    handleSpotifyError(error, res);
  }
});

// Error handling helper
function handleSpotifyError(error, res) {
  console.error('Spotify API Error:', error.response?.data || error.message);
  
  if (error.response) {
    // Forward Spotify API errors
    const { status, data } = error.response;
    
    res.status(status).json({
      success: false,
      error: {
        code: 'SPOTIFY_API_ERROR',
        message: 'Spotify API request failed',
        details: data.error?.message || 'Unknown error',
        status: status,
        reason: data.error?.reason
      },
      timestamp: new Date().toISOString()
    });
  } else if (error.code === 'ECONNABORTED') {
    // Timeout error
    res.status(504).json({
      success: false,
      error: {
        code: 'REQUEST_TIMEOUT',
        message: 'Request to Spotify API timed out',
        timeout: 30000
      },
      timestamp: new Date().toISOString()
    });
  } else {
    // Network or other errors
    res.status(500).json({
      success: false,
      error: {
        code: 'INTERNAL_ERROR',
        message: 'Failed to process Spotify request',
        details: error.message
      },
      timestamp: new Date().toISOString()
    });
  }
}
```

### **Middleware Components**

#### **Authentication Middleware**
```javascript
// middleware/authenticateToken.js
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'MISSING_TOKEN',
          message: 'Access token required'
        }
      });
    }
    
    // Verify token with your backend auth system
    const user = await verifyBackendToken(token);
    
    if (!user) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired access token'
        }
      });
    }
    
    req.user = user;
    next();
  } catch (error) {
    res.status(500).json({
      success: false,
      error: {
        code: 'AUTH_ERROR',
        message: 'Authentication failed'
      }
    });
  }
};
```

#### **Scope Validation Middleware**
```javascript
// middleware/validateScopes.js
const validateScopes = (requiredScopes) => {
  return (req, res, next) => {
    const userScopes = req.user.scopes || [];
    const hasRequiredScopes = requiredScopes.every(scope => 
      userScopes.includes(scope)
    );
    
    if (!hasRequiredScopes) {
      return res.status(403).json({
        success: false,
        error: {
          code: 'INSUFFICIENT_SCOPES',
          message: 'Missing required scopes',
          required: requiredScopes,
          available: userScopes
        }
      });
    }
    
    next();
  };
};
```

## **Frontend Integration Changes**

### **Update SpotifyAPIService.swift**

Replace the direct Spotify API call in [`fetchAvailableDevices()`](Electric Slideshow/Services/SpotifyAPIService.swift:146) with backend proxy call:

```swift
// OLD: Direct Spotify API call
let url = baseURL.appendingPathComponent("me/player/devices")

// NEW: Backend proxy call
let backendBaseURL = URL(string: "https://electric-slideshow-server.onrender.com/api/spotify")!
let url = backendBaseURL.appendingPathComponent("devices")
```

### **Update Request Headers**
The backend proxy expects backend authentication, not Spotify tokens:

```swift
// OLD: Spotify token
request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

// NEW: Backend token (assuming backend handles Spotify auth)
let backendToken = try await authService.getBackendAccessToken()
request.setValue("Bearer \(backendToken)", forHTTPHeaderField: "Authorization")
```

## **Testing Requirements**

### **Unit Tests**
1. **Scope Validation**: Test that requests without proper scopes return 403
2. **Token Validation**: Test that invalid backend tokens return 401
3. **Error Forwarding**: Test that Spotify API errors are properly forwarded
4. **Timeout Handling**: Test timeout scenarios return 504

### **Integration Tests**
1. **Happy Path**: Valid token + valid scopes → successful device list
2. **Empty Devices**: Valid token but no devices → empty array response
3. **Spotify Down**: Handle Spotify API unavailability gracefully
4. **Rate Limiting**: Handle Spotify rate limits appropriately

### **End-to-End Tests**
1. **Frontend Integration**: Test frontend can successfully fetch devices through proxy
2. **Error Display**: Test frontend properly displays backend error messages
3. **Token Refresh**: Test token refresh works with proper scopes

## **Deployment Checklist**

### **Pre-Deployment**
- [ ] Implement `/api/spotify/devices` endpoint
- [ ] Add scope validation middleware
- [ ] Update token refresh logic with proper scopes
- [ ] Add comprehensive error handling
- [ ] Implement request/response logging
- [ ] Add monitoring and alerting

### **Post-Deployment**
- [ ] Update frontend to use backend proxy
- [ ] Test device fetching functionality
- [ ] Monitor error rates and response times
- [ ] Verify scope validation works correctly
- [ ] Test token refresh with new scopes

## **Monitoring & Observability**

### **Metrics to Track**
- Request success/failure rates
- Response times (p95, p99)
- Spotify API error rates
- Token refresh success rates
- Scope validation failures

### **Logging Requirements**
- Request correlation IDs
- User identification (anonymized)
- Spotify API response codes
- Error details and stack traces
- Performance metrics

### **Alerting Thresholds**
- Error rate > 5%
- Response time p95 > 2 seconds
- Spotify API 4xx errors > 10%
- Token refresh failures > 1%

## **Security Considerations**

1. **Token Storage**: Secure storage of backend access tokens
2. **Rate Limiting**: Implement rate limiting per user/IP
3. **CORS**: Configure CORS properly for frontend origins
4. **Input Validation**: Validate all input parameters
5. **Error Sanitization**: Don't expose internal system details in errors

## **Performance Optimization**

1. **Caching**: Consider caching device lists (5-minute TTL)
2. **Connection Pooling**: Use connection pooling for Spotify API calls
3. **Timeout Configuration**: Set appropriate timeouts (30s for device calls)
4. **Retry Logic**: Implement exponential backoff for transient failures

This implementation guide addresses all identified issues and provides a robust, scalable solution for the Spotify devices API proxy functionality.