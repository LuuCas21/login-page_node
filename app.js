const dotenv = require('dotenv');
const express = require('express');
const bcrypt = require('bcrypt');
const passport = require('passport');
const flash = require('express-flash');
const session = require('express-session');
const methodOverride = require('method-override');

dotenv.config({ path: './config.env' });

const initializePassport = require('./passport-config');

const app = express();

const users = [];

initializePassport(passport, email => {
    return users.find(user => user.email === email)
}, id => {
    return users.find(user => user.id === id)
});

// We need to hash our user's passwords in order to protect their passwords.
// We're gonna use something called bcrypt.

// In order to use the ejs syntax we need to tell the server that we are using ejs.
// Now our view-engine is set to ejs.
app.set('view-engine', 'ejs');
app.use(express.urlencoded({ extended: false })); // We are telling our server that we wanna have access from the input values inside our request variable in the post method.
app.use(flash()); // We are telling our server that we are using passport.
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(methodOverride('_method'));

// init passport on every route call.
app.use(passport.initialize()); // This is gonna set up some of the basics for us.

// allow passport to use "express-session".
app.use(passport.session()); // it will persist our data across the entire session the user has

app.get('/', checkAuthenticated, (req, res) => {
    // the render() method is gonna render a file.

    res.render('index.ejs', { name: req.user.name }); // we can get our user very easily by using passport.
    // We can use this name variable in the index.ejs file.
});

app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs');
});

// we'll use the localStrategy ('local')
app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/', // where do we go if there is a success ? we go to the home page '/'.
    failureRedirect: '/login',
    failureFlash: true // it will display the messages we set up on passport-config file.
}));

app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs');
});

app.post('/register', checkNotAuthenticated, async (req, res) => {
    // I can have access to the input name by typing 'req.body.name'.
    try {
        // We'll make a hashed password
        // We can specify how many times you want to generate the hash, how secured you want it to be. 10 is the default number.
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        users.push({
            id: Date.now().toString(),
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        });
        // If all that was successful we want to redirect the user back to the login page.
        res.redirect('/login');
    } catch {
        // If there's a failure then we want to redirect the user back to the register page.
        res.redirect('/register');
    }
    console.log(users);
})

// we cannot perform delete request in the HTML form because its not supported, we can only use POST. We can use a library for that.
// This library is called method-override.
// This lib will allow us to override method that we were using
app.delete('/logout', (req, res) => {
    //req.logOut(); // we have accesss to logOut() because of passport. the logOut() function will clear our session and log the user out.
    req.logout(function(err) {  // logout of passport
		req.session.destroy(function (err) { // destroy the session
			//res.send(); // send to the client
            res.redirect('/login');
		});
	});
})

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    };

    res.redirect('/login');
};

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/');
    };

    next();
}

app.listen(3000, () => {
    console.log(`Server is running on port 3000`);
});