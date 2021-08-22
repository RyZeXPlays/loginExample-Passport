const passport = require('passport');
const User = require('../models/user');
const LocalStrategy = require('passport-local').Strategy;

passport.serializeUser((user, done) => {
	done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
	const user = await User.findById(id);
	done(null, user);
});

passport.use(
	'local-signup',
	new LocalStrategy(
		{
			usernameField: 'email',
			passwordField: 'password',
			passReqToCallback: true,
		},
		async (req, email, password, done) => {
			const user = await User.findOne({ email: email });
			if (user) {
				return done(null, false, req.flash('signupMessage', 'The email is alredy taken.'));
			} else {
				const newUser = new User();
				newUser.email = email;
				newUser.password = newUser.encryptPassword(password);
				await newUser.save();
				done(null, newUser);
			}
		}
	)
);

passport.use(
	'local-signin',
	new LocalStrategy(
		{
			usernameField: 'email',
			passwordField: 'password',
			passReqToCallback: true,
		},
		async (req, email, password, done) => {
			const user = await User.findOne({ email: email });
			if (!user) {
				done(null, false, req.flash('signinMessage', 'No user found'));
			}
			if (!user.comparePassword(password)) {
				done(null, false, req.flash('signinMessage', 'Incorret Password'));
			}
			done(null, user);
		}
	)
);
