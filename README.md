# Passport-Stateless-GitHub

[![Build](https://travis-ci.org/avbel/passport-stateless-github.png)](https://travis-ci.org/avbel/passport-stateless-github)
[![Dependencies](https://david-dm.org/avbel/passport-stateless-github.png)](https://david-dm.org/avbel/passport-stateless-github)


[Passport](http://passportjs.org/) strategy for authenticating with [GitHub](https://github.com/)
without using session.

This module lets you authenticate using GitHub in your Node.js applications via OAuth2 access token (to get is user name and password are required).
It is usefull for webapi services which are not required any web ui.


## Install

    $ npm install passport-stateless-github

## Usage

#### Configure Strategy

The stateless GitHub authentication strategy authenticates users using a GitHub account
and OAuth 2.0 tokens.  The strategy can have an optional `verify` callback, which accepts
these credentials and calls `done` providing a user, as well as `options`
specifying a client ID, client secret.

    passport.use(new StatelessGithubStrategy({
        clientID: GITHUB_CLIENT_ID,
        clientSecret: GITHUB_CLIENT_SECRET,
      },
      function(accessToken,  done) { // optional callback
        // accessToken is valid access token from github
        // do any additional verification of accessToken here (checking membership, etc)
        done();
      }
    ));

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'stateless-github'` strategy, to
authenticate requests.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get("/auth/github-protected-resource",
      passport.authenticate("stateless-github"),
      function(req, res){
        // Successful authentication
        res.json({data: [1,2,3]});
      }
    );

    app.get("/auth/signin",
      passport.authenticate("stateless-github", {
        requireAccessToken: true, //required if you want to receive access token via user name and password
        userNameField: "username", //optional name of user name field in req.body (default: userName)
        passwordField: "pwd", //optional name of password field in req.body (default: password)
        //userName: "user", password: "123" // you can pass user name and password directly here if need
        options: { //optional fields which are passed to https://api.github.com/authorizations/clients/GITHHUB_CLIENT_ID directly
          scopes: [ "read:org" ],
          note: "MyApp",
          note_url: "http://localhost"
        }
      }),
      function(req, res){
        // Send the token to user
        res.json({access_token: req.user.token});
      }
    );