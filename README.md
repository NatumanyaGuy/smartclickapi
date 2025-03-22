# Website Security Checker

A comprehensive Node.js API for analyzing website security and providing detailed security reports based on industry best practices.

## Overview

The Website Security Checker API evaluates websites across four key security dimensions:

1. **Connection Security** (25 points)

   - HTTPS implementation
   - SSL certificate validity and configuration
   - Secure HTTPS response

2. **Domain Security** (20 points)

   - Domain age verification
   - TLD reputation analysis
   - Domain name composition
   - Registration information completeness

3. **Security Headers & Configuration** (20 points)

   - Content Security Policy implementation
   - Cross-site scripting protections
   - HTTP Strict Transport Security
   - Cookie security configuration

4. **Content Safety** (20 points)
   - Redirect analysis
   - Privacy policy presence
   - Contact information availability
   - Advertisement and popup evaluation

## Getting Started

### Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Firebase account (for database)

### Installation

1. Clone the repository:

   ```
   git clone ''this repo''
   cd website-security-checker
   ```

2. Install dependencies:

   ```
   npm install
   ```

3. Set up environment variables by creating a `.env` file:

   ```
   PORT=3000
   FIREBASE_API_KEY=your_firebase_api_key
   FIREBASE_AUTH_DOMAIN=your_firebase_auth_domain
   FIREBASE_PROJECT_ID=your_firebase_project_id
   FIREBASE_STORAGE_BUCKET=your_firebase_storage_bucket
   FIREBASE_MESSAGING_SENDER_ID=your_firebase_messaging_sender_id
   FIREBASE_APP_ID=your_firebase_app_id
   FIREBASE_MEASUREMENT_ID=your_firebase_measurement_id
   ```

4. Start the server:
   ```
   npm start
   ```

## API Endpoints

### Security Check

Performs a comprehensive security check on a website.

```
POST /api/check
```

**Headers:**

- `x-api-key`: Your API key

**Request Body:**

```json
{
  "url": "example.com"
}
```

**Response:**

```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "score": 75,
  "maxScore": 85,
  "scorePercentage": 88,
  "websiteId": "abc123",
  "categories": {
    "connectionSecurity": { "score": 20, "maxScore": 25, "checks": {...} },
    "domainSecurity": { "score": 15, "maxScore": 20, "checks": {...} },
    "securityHeaders": { "score": 20, "maxScore": 20, "checks": {...} },
    "contentSafety": { "score": 20, "maxScore": 20, "checks": {...} }
  }
}
```

### User's Website History

Retrieves the history of websites checked by the authenticated user.

```
GET /api/user/websites
```

**Headers:**

- `x-api-key`: Your API key

**Response:**

```json
{
  "checkedWebsites": [
    {
      "websiteId": "abc123",
      "url": "https://example.com",
      "domain": "example.com",
      "score": 75,
      "scorePercentage": 88,
      "timestamp": "2025-03-22T12:00:00.000Z",
      "categoryScores": {
        "connectionSecurity": 20,
        "domainSecurity": 15,
        "securityHeaders": 20,
        "contentSafety": 20
      }
    }
  ]
}
```

### Website Details

Retrieves detailed results for a specific website check.

```
GET /api/websites/:id
```

**Headers:**

- `x-api-key`: Your API key

**Response:**
Detailed security check results similar to the `/api/check` response.

## Authentication

This API uses API key authentication. Each request must include the `x-api-key` header with a valid API key. The API keys are stored in the Firebase Firestore database in the `users` collection.

## Database Structure

The application uses Firebase Firestore with the following collections:

- **users**: Stores user information including API keys
- **websites**: Stores basic information about checked websites
  - **results**: Subcollection storing detailed check results for each website

## Scoring System

The security checker evaluates websites on a 85-point scale divided across four categories:

- Connection Security: 25 points
- Domain Security: 20 points
- Security Headers: 20 points
- Content Safety: 20 points

Each check within these categories is worth 5 points. The final score is presented as both a raw score and a percentage.

## Error Handling

The API includes comprehensive error handling for:

- Authentication failures
- Invalid URLs
- Network timeouts
- Failed domain lookups
- Database operation errors

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- SSL-Checker for certificate validation
- JSDOM for HTML parsing
- Axios for HTTP requests
- Whois-JSON for domain information retrieval
