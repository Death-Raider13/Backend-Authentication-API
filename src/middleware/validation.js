const Joi = require('joi');

/**
 * Validation middleware using Joi schemas
 * Provides request validation and input sanitization for security
 */

/**
 * Password validation schema with security requirements
 */
const passwordSchema = Joi.string()
  .min(8)
  .max(128)
  .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
  .required()
  .messages({
    'string.min': 'Password must be at least 8 characters long',
    'string.max': 'Password must not exceed 128 characters',
    'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (@$!%*?&)',
    'any.required': 'Password is required'
  });

/**
 * Email validation schema
 */
const emailSchema = Joi.string()
  .email({ tlds: { allow: false } })
  .max(254)
  .required()
  .messages({
    'string.email': 'Please provide a valid email address',
    'string.max': 'Email must not exceed 254 characters',
    'any.required': 'Email is required'
  });

/**
 * Phone validation schema (optional)
 */
const phoneSchema = Joi.string()
  .pattern(/^\+?[1-9]\d{1,14}$/)
  .optional()
  .messages({
    'string.pattern.base': 'Please provide a valid phone number'
  });

/**
 * OTP validation schema
 */
const otpSchema = Joi.string()
  .length(6)
  .pattern(/^\d{6}$/)
  .required()
  .messages({
    'string.length': 'OTP must be exactly 6 digits',
    'string.pattern.base': 'OTP must contain only numbers',
    'any.required': 'OTP is required'
  });

/**
 * Validation schemas for different endpoints
 */
const schemas = {
  // User registration validation
  register: Joi.object({
    email: emailSchema,
    password: passwordSchema,
    phone: phoneSchema,
    displayName: Joi.string()
      .min(2)
      .max(50)
      .pattern(/^[a-zA-Z0-9\s\-_.]+$/)
      .optional()
      .messages({
        'string.min': 'Display name must be at least 2 characters',
        'string.max': 'Display name must not exceed 50 characters',
        'string.pattern.base': 'Display name can only contain letters, numbers, spaces, hyphens, underscores, and periods'
      })
  }),

  // User login validation
  login: Joi.object({
    email: emailSchema,
    password: Joi.string()
      .min(1)
      .max(128)
      .required()
      .messages({
        'string.min': 'Password is required',
        'string.max': 'Password must not exceed 128 characters',
        'any.required': 'Password is required'
      })
  }),

  // OTP request validation
  requestOtp: Joi.object({
    email: emailSchema,
    type: Joi.string()
      .valid('signup', 'login', 'reset')
      .required()
      .messages({
        'any.only': 'OTP type must be one of: signup, login, reset',
        'any.required': 'OTP type is required'
      })
  }),

  // OTP verification validation
  verifyOtp: Joi.object({
    email: emailSchema,
    otp: otpSchema,
    type: Joi.string()
      .valid('signup', 'login', 'reset')
      .required()
      .messages({
        'any.only': 'OTP type must be one of: signup, login, reset',
        'any.required': 'OTP type is required'
      })
  }),

  // Password reset request validation
  forgotPassword: Joi.object({
    email: emailSchema
  }),

  // Password reset completion validation
  resetPassword: Joi.object({
    email: emailSchema,
    otp: otpSchema,
    newPassword: passwordSchema
  }),

  // OTP resend validation
  resendOtp: Joi.object({
    email: emailSchema,
    type: Joi.string()
      .valid('signup', 'login', 'reset')
      .required()
      .messages({
        'any.only': 'OTP type must be one of: signup, login, reset',
        'any.required': 'OTP type is required'
      })
  })
};

/**
 * Input sanitization function
 * Removes potentially harmful characters and normalizes input
 */
const sanitizeInput = (obj) => {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }

  const sanitized = {};
  
  for (const [key, value] of Object.entries(obj)) {
    if (typeof value === 'string') {
      // Trim whitespace
      let sanitizedValue = value.trim();
      
      // Remove null bytes and control characters (except newlines and tabs for some fields)
      sanitizedValue = sanitizedValue.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '');
      
      // For email fields, convert to lowercase
      if (key === 'email') {
        sanitizedValue = sanitizedValue.toLowerCase();
      }
      
      // For display name, normalize spaces
      if (key === 'displayName') {
        sanitizedValue = sanitizedValue.replace(/\s+/g, ' ');
      }
      
      sanitized[key] = sanitizedValue;
    } else if (typeof value === 'object') {
      sanitized[key] = sanitizeInput(value);
    } else {
      sanitized[key] = value;
    }
  }
  
  return sanitized;
};

/**
 * Create validation middleware for a specific schema
 * @param {string} schemaName - Name of the schema to validate against
 * @param {string} source - Source of data to validate ('body', 'query', 'params')
 * @returns {Function} Express middleware function
 */
const validate = (schemaName, source = 'body') => {
  return (req, res, next) => {
    try {
      const schema = schemas[schemaName];
      if (!schema) {
        return res.status(500).json({
          success: false,
          error: {
            code: 'VALIDATION_SCHEMA_NOT_FOUND',
            message: 'Validation schema not found'
          },
          timestamp: new Date().toISOString()
        });
      }

      // Get data from the specified source
      const dataToValidate = req[source];
      
      // Sanitize input data
      const sanitizedData = sanitizeInput(dataToValidate);
      
      // Validate against schema
      const { error, value } = schema.validate(sanitizedData, {
        abortEarly: false, // Return all validation errors
        stripUnknown: true, // Remove unknown fields
        convert: true // Convert types when possible
      });

      if (error) {
        // Format validation errors
        const validationErrors = error.details.map(detail => ({
          field: detail.path.join('.'),
          message: detail.message,
          value: detail.context?.value
        }));

        // Log validation failure for security monitoring
        console.warn('Validation failed:', {
          endpoint: req.path,
          method: req.method,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          errors: validationErrors,
          timestamp: new Date().toISOString()
        });

        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Request validation failed',
            details: validationErrors
          },
          timestamp: new Date().toISOString()
        });
      }

      // Replace original data with validated and sanitized data
      req[source] = value;
      
      next();
    } catch (err) {
      console.error('Validation middleware error:', err);
      return res.status(500).json({
        success: false,
        error: {
          code: 'VALIDATION_MIDDLEWARE_ERROR',
          message: 'Internal validation error'
        },
        timestamp: new Date().toISOString()
      });
    }
  };
};

/**
 * Generic input sanitization middleware
 * Can be used independently of schema validation
 */
const sanitize = (source = 'body') => {
  return (req, res, next) => {
    try {
      if (req[source]) {
        req[source] = sanitizeInput(req[source]);
      }
      next();
    } catch (err) {
      console.error('Sanitization middleware error:', err);
      return res.status(500).json({
        success: false,
        error: {
          code: 'SANITIZATION_ERROR',
          message: 'Input sanitization failed'
        },
        timestamp: new Date().toISOString()
      });
    }
  };
};

/**
 * Middleware to validate ObjectId parameters
 */
const validateObjectId = (paramName = 'id') => {
  return (req, res, next) => {
    const id = req.params[paramName];
    
    if (!id) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'MISSING_PARAMETER',
          message: `Parameter '${paramName}' is required`
        },
        timestamp: new Date().toISOString()
      });
    }

    // MongoDB ObjectId validation pattern
    const objectIdPattern = /^[0-9a-fA-F]{24}$/;
    
    if (!objectIdPattern.test(id)) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_OBJECT_ID',
          message: `Parameter '${paramName}' must be a valid ObjectId`
        },
        timestamp: new Date().toISOString()
      });
    }

    next();
  };
};

module.exports = {
  validate,
  sanitize,
  validateObjectId,
  schemas,
  sanitizeInput
};