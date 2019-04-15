const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
// Load our simple User model
const User = require('../models/User');
const {forwardAuthenticated} = require('../config/auth');


/*
    Extend the base User routes and add our own
 */
const MIN_PWD_LENGTH = 8; // Min Pw lengthy thing

// The main login Page
router.get('/login', forwardAuthenticated, (req, res) => res.render('login'));

// The main register page
router.get('/register', forwardAuthenticated, (req, res) => res.render('register'));

// Register a User. Make them enter the password twice for confirmation
router.post('/register', (req, res) => {
    console.log('Posted this');

    const {name, email, password, password2} = req.body;
    let errors = [];

    // Make sure they provided all fields
    if (!name || !email || !password || !password2) {
        errors.push({msg: 'Please enter all of the required Info'});
    }
    // Make sure they entered same password
    if (password !== password2) {
        errors.push({msg: `Passwords Do NOT Match!`});
    }

    // ForCe at least 8 chars in pw

    if (password.length < MIN_PWD_LENGTH) {
        errors.push({msg: `Password must be at least ${MIN_PWD_LENGTH}characters`});
    }

    // Check for any errors
    if (errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        User.findOne({email: email}).then(user => { // Make sure not already registered
            if (user) {
                errors.push({msg: 'Email already exists'});
                res.render('register', {
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
            } else {
                const newUser = new User({
                    name,
                    email,
                    password
                });

                // Generate a SALT pattern for the new user
                bcrypt.genSalt(10, (err, salt) => {
                    bcrypt.hash(newUser.password, salt, (err, hash) => {
                        if (err) throw err;
                        newUser.password = hash;
                        newUser
                            .save()
                            .then(user => {
                                req.flash( // Gussy it up
                                    'success_msg',
                                    'You are now registered and can log in'
                                );
                                res.redirect('/users/login');
                            })
                            .catch(err => console.log(err));
                    });
                });
            }
        });
    }
});

// Login a User
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

// Logout a User. Who needs em? :-P
router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are logged out');
    res.redirect('/users/login');
});

module.exports = router;
