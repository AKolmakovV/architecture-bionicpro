const express = require("express");
const { auth } = require("express-oauth2-jwt-bearer");
const cors = require("cors");
const path = require("path");

require("dotenv").config({ path: path.resolve(__dirname, ".env") });

const app = express();
const PORT = process.env.PORT || 8000;

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json());

// Для отладки
app.use((req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.substring(7);
    try {
      const payload = JSON.parse(
        Buffer.from(token.split(".")[1], "base64").toString()
      );
      console.log("   Token Info:");
      console.log("Audience:", payload.aud);
      console.log("Issuer:", payload.iss);
      console.log("Subject:", payload.sub);
      console.log("Roles:", payload.realm_access?.roles);
    } catch (e) {
      console.log("Cannot decode token");
    }
  }
  next();
});

// Middleware для обработки ошибок
const checkJwt = (req, res, next) => {
  const authMiddleware = auth({
    issuer: process.env.KEYCLOAK_ISSUER,
    audience: process.env.KEYCLOAK_AUDIENCE,
    jwksUri: `${process.env.KEYCLOAK_ISSUER}/protocol/openid-connect/certs`,
    tokenSigningAlg: "RS256",
  });

  authMiddleware(req, res, (err) => {
    if (err) {
      console.error("JWT Validation Error:", JSON.stringify(err));

      if (err.name === "UnauthorizedError") {
        return res.status(401).json({
          error: "Invalid token",
          message: "The provided token is invalid or expired",
          code: "INVALID_TOKEN",
        });
      }

      return res.status(500).json({
        error: "Authentication error",
        message: "Failed to validate token",
      });
    }

    next();
  });
};

// Проверка роли prothetic_user
const requireProtheticUserRole = (req, res, next) => {
  if (!req.auth?.payload) {
    console.log(JSON.stringify(req.auth));
    return res.status(401).json({ error: "Invalid token" });
  }

  const roles = req.auth.payload?.roles || [];
  if (!roles.includes("prothetic_user")) {
    return res.status(403).json({
      error: "Access denied. Required role: prothetic_user",
      user: req.auth.payload.preferred_username,
    });
  }

  next();
};

// защищенный endpoint
app.get("/reports", checkJwt, requireProtheticUserRole, (req, res) => {
   const reports = require('./stub.json');

    res.json({
      success: true,
      reports
    });
});

// обработка ошибок
app.use((error, req, res, next) => {
  if (error.name === "UnauthorizedError") {
    res.status(401).json({
      error: "Authentication required",
      message: "Valid JWT token is required",
    });
  } else {
    console.error("Server error:", error);
    res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.listen(PORT, () => {
  console.log(`Process ENV: \n`);
  console.log(JSON.stringify(process.env));
  console.log(`\nBackend server running on port ${PORT}`);
  console.log(`Keycloak Issuer: ${process.env.KEYCLOAK_ISSUER}`);
});
