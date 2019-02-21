import express from 'express';
import logger from 'morgan';
import cookieParser from 'cookie-parser';
import bodyParser from 'body-parser';
import session from 'express-session';
import jwtDecode from 'jwt-decode';

import passport from 'passport';

import { Strategy as SSPStrategy } from '../src';

const provider='ssp';
const authpathbase=`/auth/${provider}`;
const loginpath=`${authpathbase}/login`;
const callbackpath=`${authpathbase}/callback`;
const logoutpath=`${authpathbase}/logout`;
const failpath=`${authpathbase}/fail`;

// OAuth config
const config={
	authorizationURL : 'https://ssp.example./simplesaml/module.php/oauth2/authorize.php',
	tokenURL         : 'https://ssp.example.com/simplesaml/module.php/oauth2/access_token.php',
	profileUrl       : 'https://ssp.example.com/simplesaml/module.php/oauth2/userinfo.php',
	clientID         : 'clientID',
	clientSecret     : 'clientSecret',
	callbackURL      : 'http://localhost:3000/auth/ssp/callback'
};

const app = express();

app.use(express.static(`${__dirname}/public`));

// serialize

passport.serializeUser(function(user, done)
{
	done(null, user);
});

passport.deserializeUser(function(user, done)
{
	done(null, user);
});

const ssp=new SSPStrategy(config,
	function(accessToken, refreshToken, profile, done)
	{
		done(null, profile);
	}
);

passport.use(ssp);

// configure Express
app.set('views', `${__dirname}/views`);
app.set('view engine', 'ejs');
app.use(logger('dev'));
app.use(cookieParser());
app.use(bodyParser.json());

app.use(session(
	{
		secret            : 'titok',
		resave            : true,
		saveUninitialized : true
		// cookie            : { secure: true }
	}
));
app.use(bodyParser.urlencoded({ extended: false }));

// init middleware
app.use(passport.initialize());
app.use(passport.session());

// callback
app.get(
	callbackpath,
	passport.authenticate(provider, { failureRedirect: failpath }),
	function(req, res)
	{
		// Successful authentication, redirect home.
		const redirTo = req.session.redirectToAfterLogin || '/';

		res.redirect(redirTo);
	}
);
// login
app.get(loginpath, passport.authenticate(provider),
	function(req, res)
	{
		if (req.isAuthenticated()) console.log(req.user);
	}
);

// logout
app.get(logoutpath, function(req, res)
{
	req.logout();
	res.redirect('/');
});

app.get('/',
	function(req, res)
	{
		if (req.isAuthenticated())
		{
			let accessToken;

			try
			{
				accessToken=jwtDecode(req.user._accessToken);
			}
			catch (e)
			{
				console.log(e);
				accessToken=null;
			}
			res.render('index', { profile: req.user, accessToken: accessToken });
		}
		else res.render('index', { profile: null });
		// res.redirect(loginpath);
	}
);

app.listen(3000);
