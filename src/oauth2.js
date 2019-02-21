/**
 * Module dependencies.
 */
import { OAuth2Strategy } from 'passport-oauth';

/**
 * `Strategy` constructor.
 *
 * The ssp authentication strategy authenticates requests by
 * delegating to ssp using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientID`      your Dataporten application's client id
 *   - `clientSecret`  your Dataporten application's client secret
 *   - `callbackURL`   URL to which Dataporten will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new SSPStrategy({
 *         authorizationURL
       clientID: '_147984a9971a8e3cfca62889fc141e155d1d5f993b',
 *         clientSecret: 'shhh-its-a-secret',
 *         callbackURL: 'https://www.example.net/auth/ssp/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
class Strategy extends OAuth2Strategy
{
	constructor(options, verify)
	{
		options = options || {};
		options.authorizationURL = options.authorizationURL || '';
		options.tokenURL = options.tokenURL || '';
		options.scopeSeparator = options.scopeSeparator || ' ';
		options.customHeaders = options.customHeaders || {};
		options.sessionKey = options.sessionKey || 'oauth:ssp';
		if (!options.customHeaders['User-Agent'])
		{
			options.customHeaders['User-Agent'] = options.userAgent || 'passport-ssp';
		}
		super(options, verify);

		this.profileUrl = options.profileUrl || '';
		this.name = 'ssp';

	}

	/**
     * Retrieve user profile from SSP.
     *
     * This function constructs a normalized profile, with the following properties:
     *
	 *   - `provider`         always set to `ssp`
	 *   - `id`               the user's ID
     *   - `displayName`      the user's display name
     *   - `_json`            the raw
     *
     * @param {String} accessToken
     * @param {Function} done
     * @api protected
     */
	userProfile(accessToken, done)
	{
		this._oauth2.useAuthorizationHeaderforGET(true);
		this._oauth2.get(this.profileUrl, accessToken, function(err, body, res)
		{
			if (err)
			{
				return done(err);
			}
			else
			{
				try
				{
					const json = JSON.parse(body);
					const profile= { provider: 'ssp' };

					if (json.hasOwnProperty('attributes'))
					{
						profile.attributes={};
						Object.entries(json.attributes).forEach(
							([ key, value ]) =>
							{
								switch (key)
								{
									case 'eduPersonPrincipalName':
									case 'eduPersonTargetedID':
									case 'eduPersonUniqueId':
										profile.id = value;
										break;

									case 'displayName':
										profile.displayName = value;
										break;

									case 'givenName':
										profile.givenName = value;
										break;

									case 'sn':
										profile.name.familyName = value;
										break;

									case 'mail':
										profile['emails'] = [ { 'value': value,	'type': 'work' } ];
										break;

									case 'jpegPhoto':
										profile['photos'] = [ { 'value': value } ];
										break;
								}
								profile.attributes[key]=value;

							});
					}

					// profile._raw = body;
					profile._json = json;
					profile._accessToken = accessToken;
					done(null, profile);
				}
				catch (e)
				{
					done(e);
				}
			}
		});
	}

}

/**
 * Expose `Strategy`.
 */
export default Strategy;
