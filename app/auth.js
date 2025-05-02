const express = require('express');
const passport = require('passport');
const DiscordStrategy = require('passport-discord').Strategy;
const axios = require('axios');
const randomstring = require("randomstring");
const router = express.Router();

const { db } = require('../function/db');
const { logError } = require('../function/logError');

// HydraPanel Configuration
const hydrapanel = {
  url: process.env.PANEL_URL?.endsWith('/') 
    ? process.env.PANEL_URL.slice(0, -1) 
    : process.env.PANEL_URL,
  key: process.env.PANEL_KEY
};

// 1. Passport Discord Strategy Configuration
passport.use(new DiscordStrategy({
  clientID: process.env.DISCORD_CLIENT_ID,
  clientSecret: process.env.DISCORD_CLIENT_SECRET,
  callbackURL: process.env.DISCORD_CALLBACK_URL,
  scope: ['identify', 'email'],
  passReqToCallback: true
}, (req, accessToken, refreshToken, profile, done) => {
  // Convert Discord profile to local user format
  const user = {
    id: profile.id,
    username: profile.username,
    email: profile.email,
    avatar: profile.avatar
  };
  return done(null, user);
}));

// 2. Serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.get(`user-${id}`);
    done(null, user || null);
  } catch (err) {
    done(err, null);
  }
});

// 3. Account Management Functions
async function handleHydraAccount(email, username, discordId) {
  try {
    // Check if user exists
    const userId = await db.get(`id-${email}`);
    if (userId) return userId;

    // Create new account
    const password = randomstring.generate({
      length: parseInt(process.env.PASSWORD_LENGTH) || 12,
      charset: 'alphanumeric'
    });

    const response = await axios.post(`${hydrapanel.url}/api/auth/create-user`, {
      username,
      email,
      password,
      userId: discordId
    }, {
      headers: {
        'x-api-key': hydrapanel.key,
        'Content-Type': 'application/json'
      }
    });

    // Save credentials
    await db.set(`id-${email}`, response.data.userId);
    await db.set(`user-${discordId}`, {
      id: discordId,
      email,
      username,
      hydraId: response.data.userId
    });

    return response.data.userId;
  } catch (error) {
    if (error.response?.status === 409) {
      // User already exists
      const existingId = error.response.data.userId;
      await db.set(`id-${email}`, existingId);
      return existingId;
    }
    throw error;
  }
}

// 4. Routes
router.get('/login/discord', (req, res, next) => {
  req.session.returnTo = req.query.returnTo || '/dashboard';
  passport.authenticate('discord')(req, res, next);
});

router.get('/callback/discord', 
  passport.authenticate('discord', { 
    failureRedirect: '/login?error=discord_auth_failed' 
  }),
  async (req, res) => {
    try {
      if (!req.user?.email) {
        throw new Error('No email from Discord');
      }

      await handleHydraAccount(
        req.user.email,
        req.user.username,
        req.user.id
      );

      res.redirect(req.session.returnTo || '/dashboard');
    } catch (error) {
      logError('Auth callback failed', error);
      res.redirect('/login?error=account_setup_failed');
    }
  }
);

router.get('/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy();
    res.redirect('/');
  });
});

module.exports = router;
