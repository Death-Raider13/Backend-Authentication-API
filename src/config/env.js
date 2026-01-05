require('dotenv').config();

const requiredEnvVars = [
  'MONGODB_URI',
  'JWT_SECRET',
  'JWT_EXPIRES_IN',
  'OTP_EXPIRY_MINUTES',
  'BCRYPT_SALT_ROUNDS'
];

const validateEnvironment = () => {
  console.log('🔍 Validating environment configuration...');
  
  // Check for missing required variables
  const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);
  
  if (missingVars.length > 0) {
    throw new Error(`❌ Missing required environment variables: ${missingVars.join(', ')}`);
  }

  // Validate JWT secret strength
  if (process.env.JWT_SECRET.length < 32) {
    console.warn('⚠️  JWT_SECRET should be at least 32 characters long for production use');
  }

  // Validate numeric values
  const numericVars = {
    PORT: process.env.PORT || 3000,
    OTP_EXPIRY_MINUTES: process.env.OTP_EXPIRY_MINUTES,
    BCRYPT_SALT_ROUNDS: process.env.BCRYPT_SALT_ROUNDS,
    RATE_LIMIT_WINDOW_MS: process.env.RATE_LIMIT_WINDOW_MS || 900000,
    RATE_LIMIT_MAX_REQUESTS: process.env.RATE_LIMIT_MAX_REQUESTS || 3
  };

  for (const [key, value] of Object.entries(numericVars)) {
    if (isNaN(Number(value))) {
      throw new Error(`❌ Environment variable ${key} must be a valid number, got: ${value}`);
    }
  }

  // Validate environment-specific settings
  const nodeEnv = process.env.NODE_ENV || 'development';
  if (nodeEnv === 'production') {
    if (process.env.JWT_SECRET.includes('change-this') || process.env.JWT_SECRET.includes('your-super-secret')) {
      throw new Error('❌ JWT_SECRET must be changed from default value in production');
    }
    
    if (!process.env.MONGODB_URI.includes('mongodb://') && !process.env.MONGODB_URI.includes('mongodb+srv://')) {
      throw new Error('❌ MONGODB_URI must be a valid MongoDB connection string');
    }
  }

  console.log('✅ Environment validation passed');
  console.log(`📊 Configuration loaded for ${nodeEnv} environment`);
};

const config = {
  // Server configuration
  port: parseInt(process.env.PORT) || 3000,
  nodeEnv: process.env.NODE_ENV || 'development',
  
  // Application metadata
  app: {
    name: process.env.APP_NAME || 'Backend Authentication Service',
    version: process.env.APP_VERSION || '1.0.0'
  },
  
  // Database configuration
  mongodb: {
    uri: process.env.MONGODB_URI,
    testUri: process.env.MONGODB_TEST_URI
  },
  
  // JWT configuration
  jwt: {
    secret: process.env.JWT_SECRET,
    expiresIn: process.env.JWT_EXPIRES_IN
  },
  
  // OTP configuration
  otp: {
    expiryMinutes: parseInt(process.env.OTP_EXPIRY_MINUTES)
  },
  
  // Rate limiting configuration
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 3
  },
  
  // Security configuration
  bcrypt: {
    saltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS)
  },
  
  // CORS configuration
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    credentials: process.env.CORS_CREDENTIALS === 'true'
  },
  
  // Logging configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    enableRequestLogging: process.env.ENABLE_REQUEST_LOGGING === 'true'
  }
};

module.exports = {
  config,
  validateEnvironment
};