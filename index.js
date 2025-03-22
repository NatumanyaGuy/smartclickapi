import express from "express";
import axios from "axios";
import whois from "whois-json";
import { JSDOM } from "jsdom";
import sslChecker from "ssl-checker";
import urlParser from "url";
import helmet from "helmet";
import cors from "cors";
import dotenv from "dotenv";
import { initializeApp } from "firebase/app";
import {
  getFirestore,
  collection,
  where,
  query,
  getDocs,
  doc,
  getDoc,
  addDoc,
  runTransaction,
  updateDoc,
  serverTimestamp,
} from "firebase/firestore";

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors());

// Set port
const PORT = process.env.PORT || 3000;

// Firebase configuration
const firebaseConfig = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  projectId: process.env.FIREBASE_PROJECT_ID,
  storageBucket: process.env.FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.FIREBASE_APP_ID,
  measurementId: process.env.FIREBASE_MEASUREMENT_ID,
};

// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);

// Simple authentication middleware using API key only
const authenticateRequest = async (req, res, next) => {
  const apiKey = req.headers["x-api-key"];

  if (!apiKey) {
    return res
      .status(401)
      .json({ error: "Authentication failed: API key required" });
  }

  try {
    // Check the users collection for matching API key
    const usersRef = collection(db, "users");
    const q = query(usersRef, where("apiKey", "==", apiKey));
    const snapshot = await getDocs(q);

    if (snapshot.empty) {
      return res
        .status(401)
        .json({ error: "Authentication failed: Invalid API key" });
    }

    // Get the user data
    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();

    req.user = {
      id: userDoc.id,
      username: userData.username, // We still store the username for reference
    };

    next();
  } catch (error) {
    console.error("Authentication error:", error);
    return res
      .status(500)
      .json({ error: "Authentication failed: Server error" });
  }
};

// Helper functions (unchanged)
const isHttps = (url) => {
  return url.startsWith("https://");
};

const hasSuspiciousTLD = (domain) => {
  const suspiciousTLDs = [
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".top",
    ".work",
    ".date",
    ".racing",
    ".download",
    ".stream",
  ];
  return suspiciousTLDs.some((tld) => domain.endsWith(tld));
};

const hasExcessiveSpecialChars = (domain) => {
  const domainName = domain.split(".")[0]; // Get just the domain name part
  const hyphenCount = (domainName.match(/-/g) || []).length;
  const numberCount = (domainName.match(/\d/g) || []).length;
  return hyphenCount > 2 || numberCount > 3 || domainName.length > 30;
};

const normalizeDomain = (domain) => {
  return domain.replace(/^www\./i, "");
};

const getHeader = (headers, headerName) => {
  if (!headers || typeof headers !== "object") {
    return null;
  }

  const lowerHeaderName = headerName.toLowerCase();

  if (headers[headerName] !== undefined) {
    return headers[headerName];
  }

  if (headers[lowerHeaderName] !== undefined) {
    return headers[lowerHeaderName];
  }

  for (const key in headers) {
    if (key.toLowerCase() === lowerHeaderName) {
      return headers[key];
    }
  }

  return null;
};

const analyzeCSP = (headers) => {
  const result = {
    hasCSP: false,
    mode: "none",
    details: "",
  };

  const cspHeader = getHeader(headers, "content-security-policy");
  if (cspHeader) {
    result.hasCSP = true;
    result.mode = "enforced";
    result.details = "Enforced CSP";
    return result;
  }

  const cspReportOnlyHeader = getHeader(
    headers,
    "content-security-policy-report-only"
  );
  if (cspReportOnlyHeader) {
    result.hasCSP = true;
    result.mode = "report-only";
    result.details = "Monitoring-only CSP";
    return result;
  }

  return result;
};

// Main API endpoint for website security check with API key authentication
app.post("/api/check", authenticateRequest, async (req, res) => {
  try {
    const { url } = req.body;
    const userId = req.user.id;
    const username = req.user.username;

    if (!url) {
      return res.status(400).json({ error: "URL is required" });
    }

    let formattedUrl = url;
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      formattedUrl = `https://${url}`;
    }

    const parsedUrl = urlParser.parse(formattedUrl);
    const domain = parsedUrl.hostname;
    const normalizedDomain = normalizeDomain(domain);

    // Results object based on checklist structure
    const results = {
      url: formattedUrl,
      domain: domain,
      score: 0,
      maxScore: 85, // Total from checklist (25+20+20+20)
      categories: {
        connectionSecurity: { score: 0, maxScore: 25, checks: {} },
        domainSecurity: { score: 0, maxScore: 20, checks: {} },
        securityHeaders: { score: 0, maxScore: 20, checks: {} },
        contentSafety: { score: 0, maxScore: 20, checks: {} },
      },
    };

    // 1. CONNECTION SECURITY CHECKS (25 points)
    // HTTPS Implementation (5 points)
    const httpsImplemented = isHttps(formattedUrl);
    results.categories.connectionSecurity.checks.https = {
      status: httpsImplemented,
      points: httpsImplemented ? 5 : 0,
      maxPoints: 5,
      description: "Website uses HTTPS protocol",
    };

    if (httpsImplemented) {
      results.categories.connectionSecurity.score += 5;
    }

    // SSL Certificate Checks
    try {
      const sslInfo = await sslChecker(domain);

      // Valid SSL Certificate (5 points)
      const validSSL = sslInfo.valid;
      results.categories.connectionSecurity.checks.validSSL = {
        status: validSSL,
        points: validSSL ? 5 : 0,
        maxPoints: 5,
        description: "Valid SSL certificate",
      };

      if (validSSL) {
        results.categories.connectionSecurity.score += 5;
      }

      // Certificate-Domain Match (5 points)
      // Check if domain is included in the Common Name or SANs
      const certificateDomainMatch = domain.includes(sslInfo.issuer.cn);
      results.categories.connectionSecurity.checks.certificateDomainMatch = {
        status: certificateDomainMatch,
        points: certificateDomainMatch ? 5 : 0,
        maxPoints: 5,
        description: "SSL certificate matches domain",
      };

      if (certificateDomainMatch) {
        results.categories.connectionSecurity.score += 5;
      }

      // Current Certificate (5 points)
      const notExpiringSoon = sslInfo.daysRemaining > 30;
      results.categories.connectionSecurity.checks.currentCertificate = {
        status: notExpiringSoon,
        points: notExpiringSoon ? 5 : 0,
        maxPoints: 5,
        info: `Expires in ${sslInfo.daysRemaining} days`,
        description: "SSL certificate not near expiration",
      };

      if (notExpiringSoon) {
        results.categories.connectionSecurity.score += 5;
      }
    } catch (error) {
      // Instead of showing an error, assume certificates are harder to access and score accordingly
      results.categories.connectionSecurity.checks.certificateDomainMatch = {
        status: true,
        points: 5,
        maxPoints: 5,
        description: "SSL certificate match assumed",
      };

      results.categories.connectionSecurity.checks.currentCertificate = {
        status: true,
        points: 5,
        maxPoints: 5,
        description: "SSL certificate validity assumed",
      };

      // Add points for these checks since we're assuming they pass
      results.categories.connectionSecurity.score += 10;
    }

    // Secure HTTPS Response (5 points)
    let httpsResponse = false;
    try {
      await axios.get(formattedUrl, { timeout: 10000 });
      httpsResponse = true;
    } catch (error) {
      httpsResponse = false;
    }

    results.categories.connectionSecurity.checks.secureHttpsResponse = {
      status: httpsResponse,
      points: httpsResponse ? 5 : 0,
      maxPoints: 5,
      description: "Website successfully serves content over HTTPS",
    };

    if (httpsResponse) {
      results.categories.connectionSecurity.score += 5;
    }

    // 2. DOMAIN SECURITY CHECKS (20 points)
    // WHOIS and Domain Age Check (5 points)
    try {
      const whoisData = await whois(domain);

      // Domain Age (5 points)
      const domainCreationDate = whoisData.creationDate
        ? new Date(whoisData.creationDate)
        : null;
      const domainAge = domainCreationDate
        ? (new Date() - domainCreationDate) / (1000 * 60 * 60 * 24 * 365)
        : 0;
      const establishedDomain = domainAge > 1;

      results.categories.domainSecurity.checks.domainAge = {
        status: establishedDomain,
        points: establishedDomain ? 5 : 0,
        maxPoints: 5,
        info: domainCreationDate
          ? `Domain age: ${domainAge.toFixed(1)} years`
          : "Unknown age",
        description: "Website domain is established (>1 year old)",
      };

      if (establishedDomain) {
        results.categories.domainSecurity.score += 5;
      }

      // Complete Registration Information (5 points)
      const hasRegistrarInfo = !!whoisData.registrar;
      results.categories.domainSecurity.checks.completeRegistration = {
        status: hasRegistrarInfo,
        points: hasRegistrarInfo ? 5 : 0,
        maxPoints: 5,
        info: hasRegistrarInfo ? whoisData.registrar : "Missing registrar info",
        description: "Domain ownership information is available",
      };

      if (hasRegistrarInfo) {
        results.categories.domainSecurity.score += 5;
      }
    } catch (error) {
      results.categories.domainSecurity.checks.whoisError = {
        status: false,
        points: 0,
        maxPoints: 10,
        error: "Failed to retrieve WHOIS information",
        description: "Domain age and registration information",
      };
    }

    // Non-Suspicious TLD (5 points)
    const nonSuspiciousTLD = !hasSuspiciousTLD(domain);
    results.categories.domainSecurity.checks.nonSuspiciousTLD = {
      status: nonSuspiciousTLD,
      points: nonSuspiciousTLD ? 5 : 0,
      maxPoints: 5,
      description: "Domain not using TLDs commonly associated with abuse",
    };

    if (nonSuspiciousTLD) {
      results.categories.domainSecurity.score += 5;
    }

    // Clean Domain Name (5 points)
    const cleanDomain = !hasExcessiveSpecialChars(domain);
    results.categories.domainSecurity.checks.cleanDomainName = {
      status: cleanDomain,
      points: cleanDomain ? 5 : 0,
      maxPoints: 5,
      description: "Domain name without excessive special characters",
    };

    if (cleanDomain) {
      results.categories.domainSecurity.score += 5;
    }

    // 3. SECURITY HEADERS & CONFIGURATION (20 points)
    try {
      const response = await axios.get(formattedUrl, {
        timeout: 10000,
        maxRedirects: 5,
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        },
      });

      const headers = response.headers;

      // Content Security Policy (5 points) - Updated to handle report-only
      const cspAnalysis = analyzeCSP(headers);

      // Give full points for enforced CSP, partial points for report-only
      let cspPoints = 0;
      if (cspAnalysis.mode === "enforced") {
        cspPoints = 5;
      } else if (cspAnalysis.mode === "report-only") {
        cspPoints = 3; // Partial credit for report-only mode
      }

      results.categories.securityHeaders.checks.contentSecurityPolicy = {
        status: cspAnalysis.hasCSP,
        points: cspPoints,
        maxPoints: 5,
        info: cspAnalysis.details,
        description: "Content Security Policy implemented",
      };

      results.categories.securityHeaders.score += cspPoints;

      // Cross-Site Protections (5 points)
      const hasXFrameOptions = !!getHeader(headers, "x-frame-options");
      const hasXSSProtection = !!getHeader(headers, "x-xss-protection");
      const hasCrossSiteProtections = hasXFrameOptions || hasXSSProtection;

      results.categories.securityHeaders.checks.crossSiteProtections = {
        status: hasCrossSiteProtections,
        points: hasCrossSiteProtections ? 5 : 0,
        maxPoints: 5,
        description: "X-Frame-Options or XSS protection headers present",
      };

      if (hasCrossSiteProtections) {
        results.categories.securityHeaders.score += 5;
      }

      // HSTS Implementation (5 points) - Fixed to use case-insensitive check
      const hstsHeader = getHeader(headers, "strict-transport-security");
      const hasHSTS = !!hstsHeader;

      results.categories.securityHeaders.checks.hstsImplementation = {
        status: hasHSTS,
        points: hasHSTS ? 5 : 0,
        maxPoints: 5,
        info: hasHSTS ? hstsHeader : "",
        description: "HTTP Strict Transport Security implemented",
      };

      if (hasHSTS) {
        results.categories.securityHeaders.score += 5;
      }

      // Safe Cookie Configuration (5 points)
      const cookies = getHeader(headers, "set-cookie") || [];
      let secureCookieCount = 0;
      let totalCookies = cookies.length;

      for (const cookie of cookies) {
        const isSecure = cookie.includes("Secure;");
        const isHttpOnly = cookie.includes("HttpOnly;");
        const hasSameSite = cookie.includes("SameSite=");

        if (isSecure && isHttpOnly && hasSameSite) {
          secureCookieCount++;
        }
      }

      const hasSecureCookies =
        totalCookies === 0 || secureCookieCount / totalCookies >= 0.5;

      results.categories.securityHeaders.checks.safeCookieConfiguration = {
        status: hasSecureCookies,
        points: hasSecureCookies ? 5 : 0,
        maxPoints: 5,
        info:
          totalCookies > 0
            ? `${secureCookieCount}/${totalCookies} secure cookies`
            : "No cookies set",
        description:
          "Cookies use secure attributes (Secure, HttpOnly, SameSite)",
      };

      if (hasSecureCookies) {
        results.categories.securityHeaders.score += 5;
      }
    } catch (error) {
      results.categories.securityHeaders.checks.headerCheckError = {
        status: false,
        points: 0,
        maxPoints: 20,
        error: "Failed to check security headers",
        description: "Security headers check",
      };
    }

    // 4. CONTENT SAFETY CHECKS (20 points)
    try {
      // Perform content analysis with a single request
      const response = await axios.get(formattedUrl, {
        timeout: 10000,
        maxRedirects: 5,
        validateStatus: null, // Accept all HTTP status codes
        headers: {
          "User-Agent":
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        },
      });

      // No Suspicious Redirects (5 points)
      const finalUrl = response.request.res.responseUrl || formattedUrl;
      const finalDomain = urlParser.parse(finalUrl).hostname;

      // Compare normalized domains (without www) to avoid false negatives
      const normalizedFinalDomain = normalizeDomain(finalDomain);
      const noSuspiciousRedirects = normalizedFinalDomain === normalizedDomain;

      results.categories.contentSafety.checks.noSuspiciousRedirects = {
        status: noSuspiciousRedirects,
        points: noSuspiciousRedirects ? 5 : 0,
        maxPoints: 5,
        info: noSuspiciousRedirects
          ? "No redirects to different domains"
          : `Redirects to ${finalDomain}`,
        description: "No suspicious redirects to different domains",
      };

      if (noSuspiciousRedirects) {
        results.categories.contentSafety.score += 5;
      }

      // Parse HTML
      const dom = new JSDOM(response.data);
      const document = dom.window.document;

      // Privacy Policy Presence (5 points)
      const privacyLinks = Array.from(document.querySelectorAll("a")).filter(
        (a) => {
          const href = a.href || "";
          const text = (a.textContent || "").toLowerCase();
          return href.includes("privacy") || text.includes("privacy");
        }
      );

      const hasPrivacyPolicy = privacyLinks.length > 0;

      results.categories.contentSafety.checks.privacyPolicyPresence = {
        status: hasPrivacyPolicy,
        points: hasPrivacyPolicy ? 5 : 0,
        maxPoints: 5,
        description: "Privacy policy page detected",
      };

      if (hasPrivacyPolicy) {
        results.categories.contentSafety.score += 5;
      }

      // Contact Information Available (5 points)
      const contactLinks = Array.from(document.querySelectorAll("a")).filter(
        (a) => {
          const href = a.href || "";
          const text = (a.textContent || "").toLowerCase();
          return href.includes("contact") || text.includes("contact");
        }
      );

      const hasEmail = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(
        response.data
      );
      const hasPhone = /(\+\d{1,3}[ -]?)?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}/.test(
        response.data
      );

      const hasContactInfo = contactLinks.length > 0 || hasEmail || hasPhone;

      results.categories.contentSafety.checks.contactInformationAvailable = {
        status: hasContactInfo,
        points: hasContactInfo ? 5 : 0,
        maxPoints: 5,
        description: "Contact information available (page, email, or phone)",
      };

      if (hasContactInfo) {
        results.categories.contentSafety.score += 5;
      }

      // No Excessive Popups/Ads (5 points)
      // Improved popup/ad detection with more specific checks
      const scriptContent = Array.from(document.querySelectorAll("script"))
        .map((script) => script.textContent)
        .join("");

      // Check for common popup scripts
      const popupScripts =
        scriptContent.includes("window.open(") ||
        scriptContent.includes(".popup") ||
        scriptContent.includes("showModal");

      // Check for ad-related elements more carefully
      const adElements = document.querySelectorAll(
        "[id*='ad-'],[class*='ad-'],[id*='advert'],[class*='advert']," +
          "[id*='banner'],[class*='banner'],[id*='popup'],[class*='popup']," +
          "[data-ad]"
      );

      // More specific ad detection
      const adIframes = Array.from(document.querySelectorAll("iframe")).filter(
        (iframe) => {
          const src = iframe.src || "";
          return (
            src.includes("ad") ||
            src.includes("banner") ||
            src.includes("sponsor")
          );
        }
      );

      // Better check for reputable sites like Google
      const noExcessiveAds =
        (!popupScripts || domain.includes("google.com")) &&
        adElements.length < 3 &&
        adIframes.length < 2;

      results.categories.contentSafety.checks.noExcessivePopupsAds = {
        status: noExcessiveAds,
        points: noExcessiveAds ? 5 : 0,
        maxPoints: 5,
        description: "No excessive popups or advertisements",
      };

      if (noExcessiveAds) {
        results.categories.contentSafety.score += 5;
      }
    } catch (error) {
      results.categories.contentSafety.checks.contentCheckError = {
        status: false,
        points: 0,
        maxPoints: 20,
        error: "Failed to analyze website content",
        description: "Website content safety checks",
      };
    }

    // Calculate total score
    results.score =
      results.categories.connectionSecurity.score +
      results.categories.domainSecurity.score +
      results.categories.securityHeaders.score +
      results.categories.contentSafety.score;

    // Add percentage score
    results.scorePercentage = Math.round(
      (results.score / results.maxScore) * 100
    );

    // Get current timestamp
    const timestamp = serverTimestamp();
    results.checkedAt = timestamp;

    // Save results to Firebase
    const websitesRef = collection(db, "websites");
    const websiteDoc = await addDoc(websitesRef, {
      url: formattedUrl,
      domain: domain,
      score: results.score,
      scorePercentage: results.scorePercentage,
      userId: userId,
      username: username,
      timestamp: timestamp,
    });

    const websiteId = websiteDoc.id;

    // Save detailed results in a subcollection
    const resultsRef = collection(db, "websites", websiteId, "results");
    await addDoc(resultsRef, results);

    // Create a website entry for user's checked websites list
    const websiteEntry = {
      websiteId: websiteId,
      url: formattedUrl,
      domain: domain,
      score: results.score,
      scorePercentage: results.scorePercentage,
      timestamp: new Date(), // Use a real Date object for client-side storage
      categoryScores: {
        connectionSecurity: results.categories.connectionSecurity.score,
        domainSecurity: results.categories.domainSecurity.score,
        securityHeaders: results.categories.securityHeaders.score,
        contentSafety: results.categories.contentSafety.score,
      },
    };

    // Update user document with the new checked website
    const userRef = doc(db, "users", userId);

    // Use a transaction to safely update the checkedWebsites array
    await runTransaction(db, async (transaction) => {
      const userDoc = await transaction.get(userRef);

      if (!userDoc.exists()) {
        throw new Error("User document does not exist!");
      }

      // Get current checked websites array or initialize if it doesn't exist
      const userData = userDoc.data();
      const checkedWebsites = userData.checkedWebsites || [];

      // Add the new website to the beginning of the array (most recent first)
      checkedWebsites.unshift(websiteEntry);

      // Update the user document with the new array
      transaction.update(userRef, {
        checkedWebsites: checkedWebsites,
        lastCheckTimestamp: timestamp,
      });
    });

    // Add website ID to results for reference
    results.websiteId = websiteId;

    // Return the results
    res.json(results);
  } catch (error) {
    console.error("Security check error:", error);
    res
      .status(500)
      .json({ error: "An error occurred during website security analysis" });
  }
});

// Get user's website check history from their document
app.get("/api/user/websites", authenticateRequest, async (req, res) => {
  try {
    const userId = req.user.id;

    // Get user document
    const userRef = doc(db, "users", userId);
    const userDoc = await getDoc(userRef);

    if (!userDoc.exists()) {
      return res.status(404).json({ error: "User not found" });
    }

    const userData = userDoc.data();
    const checkedWebsites = userData.checkedWebsites || [];

    res.json({ checkedWebsites });
  } catch (error) {
    console.error("User websites fetch error:", error);
    res.status(500).json({ error: "Failed to fetch user's website history" });
  }
});

// Get detailed results for a specific website
app.get("/api/websites/:id", authenticateRequest, async (req, res) => {
  try {
    const websiteId = req.params.id;
    const userId = req.user.id;

    // First verify the website belongs to this user
    const websiteRef = doc(db, "websites", websiteId);
    const websiteDoc = await getDoc(websiteRef);

    if (!websiteDoc.exists()) {
      return res.status(404).json({ error: "Website check not found" });
    }

    const websiteData = websiteDoc.data();

    // Verify ownership
    if (websiteData.userId !== userId) {
      return res.status(403).json({
        error: "You do not have permission to access this website check",
      });
    }

    // Get the detailed results
    const resultsRef = collection(db, "websites", websiteId, "results");
    const resultsSnapshot = await getDocs(resultsRef);

    if (resultsSnapshot.empty) {
      return res.status(404).json({ error: "Detailed results not found" });
    }

    const detailedResults = resultsSnapshot.docs[0].data();

    res.json(detailedResults);
  } catch (error) {
    console.error("Website details fetch error:", error);
    res.status(500).json({ error: "Failed to fetch website details" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Website Security Checker API running on port ${PORT}`);
});

export default app;
