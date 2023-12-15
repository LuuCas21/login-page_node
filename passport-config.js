const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');

function initialize (passport, getUserByEmail, getUserById) {
    // The username is by default set to usernameField, but in our case we want it to be our email field.
    // We'll pass a second argument which is going to be a function that will be called to authenticate our user. This function will be called authenticateUser()
    const authenticateUser = async (email, password, done) => {
        // remember, the 'email' argument is the 'usernameField'.
        // The 'done' function will get called once we're done authenticating the user.
        const user = getUserByEmail(email);

        if (user == null) {
            return done(null, false, { message: 'No user with that email' }); // we'll return null, because there's no error in the server, and false because we found no user, and we'll return a display message.
        };

        try {
            if (await bcrypt.compare(password, user.password)) {
                // if that returns true it means the user is authenticated.
                return done(null, user); // if it is true we want to return the user we want to authenticate
            } else {
                return done(null, false, { message: 'Password incorrect '});
            }
        } catch(e) {
            done(e);
        }
    };

    passport.use(new LocalStrategy({ usernameField: 'email' }, authenticateUser)); // it will contain the steps to authenticated a user and it will return the authenticated user.
    passport.serializeUser((user, done) => done(null, user.id));
    passport.deserializeUser((id, done) => done(null, getUserById(id)));
};

module.exports = initialize;