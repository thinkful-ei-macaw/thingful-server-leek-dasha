/* eslint-disable strict */
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('../src/config');

const AuthService = {
  getUserWithName(db, user_name) {
    returndb('thingful_users')
      .where({ user_name })
      .first();
  },
    
  comparePasswords(password, hash) {
    return bcrypt.compare(password, hash);
  },

  parseBasicToken(token) {
    return Buffer
      .from(token, 'base64')
      .toString()
      .split(':');
  },
  
  createJwt(subject, payload) {
    return jwt.sign(payload, config.JWT_SECRET, {
      algorithms: ['HS256']
    });
  }
};

module.exports = AuthService;