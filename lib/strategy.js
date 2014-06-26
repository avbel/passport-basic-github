"use strict";
var util = require("util");
var Strategy = require("passport").Strategy;
var url = require("url");
var request = require("superagent");


var GITHUB  = "https://api.github.com";

function StatelessGithubStrategy(options, verify){
  Strategy.call(this);
  this.name = "stateless-github";
  this.options = options || {};
  if(!this.options.clientId){
    this.options.clientId = this.options.clientID;
  }
  if(!this.options.clientId){
    throw new Error("Missing required option 'clientId'");
  }
  if(!this.options.clientSecret){
    throw new Error("Missing required option 'clientSecret'");
  }
  this.verify = verify || this.options.verify;
}

util.inherits(StatelessGithubStrategy, Strategy);

StatelessGithubStrategy.prototype.authenticate = function(req, options) {
  var tokenUrl;
  var self = this;
  options = options || {};
  if(options.requireAccessToken){
    var k, loginOptions = options.options || {}, data = {client_secret: this.options.clientSecret};
    var body = req.body || {};
    for(k in loginOptions){
      data[k] = loginOptions[k];
    }
    tokenUrl = url.resolve(GITHUB, "/authorizations/clients/" + this.options.clientId);
    return request.put(tokenUrl).auth(body[options.userNameField || "userName"] || options.userName, body[options.passwordField || "password"] || options.password).send(data).end(function(err, response){
      if(err){
        return self.fail(err);
      }
      if(response.statusCode === 422) {
        return self.fail("Github seems to be configured with a bad client configuration.");
      }
      else if (response.statusCode === 201 || response.statusCode === 200) {
        return self.success({token: response.body.token});
      }
      self.fail(response.statusCode);
    });
  }
  var authorization = (req.headers || {})["authorization"];
  if (!authorization) {
    return this.fail(401);
  }
  var parts = authorization.split(" ");
  var token = parts[parts.length - 1];
  if(!token){
    return this.fail(400);
  }
  tokenUrl = url.resolve(GITHUB, "/applications/" + this.options.clientId + "/tokens/" + token);
  request.get(tokenUrl).auth(this.options.clientId, this.options.clientSecret).end(function(err, response){
    if(err){
      return self.fail(err);
    }
    if (response.statusCode === 200) {
      if(self.verify){
        return self.verify(token, function(err, result){
          if(err){
            return self.fail(err);
          }
          if(result === false){
            return self.fail(403);
          }
          result = result || {};
          result.token = token;
          return self.success(result);
        });
      }
      else{
        return self.success({token: token});
      }
    }
    self.fail(response.statusCode);
  });
};

StatelessGithubStrategy.GITHUB = GITHUB;

module.exports = StatelessGithubStrategy;
