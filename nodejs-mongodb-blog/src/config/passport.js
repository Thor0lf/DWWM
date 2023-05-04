const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const User = require('../models/user.model');

passport.use(new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
}, async (email, password, done) => {
    User.findOne({ email: email.toLowerCase() }, function(err, user) {
        if (err) { return done(err, {message: 'Erreur'}); }
        if (!user) { return done(null, false, { message: `L'utilisateur n'a pas été trouvé !` }); }
        if (!user.matchPassword(password)) { return done(null, false, { message: 'Le mot de passe est incorrecte !' }); }
        if (!user.isValid) { return done(null, false, {message: `L'adresse email n'a pas été validée !`})}
        return done(null, user);
    })
}));

passport.serializeUser((user, done) => {
    done(null, user._id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        if (!user) {
            return done(null, false, {message: `L'utilisateur n'a pas été trouvé !`});
        } else {
            const userInformation = {
                fullname: user.fullname,
                email: user.email,
                _id: user.id,
                role: user.role
        }
        done(err, userInformation);
        }
    });
});