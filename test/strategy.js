var Strategy = require("../lib").Strategy;
var nock = require("nock");

var CLIENT_ID     = "mock_client_id";
var CLIENT_SECRET = "mock_client_secret";
var CLIENT_TOKEN  = (new Buffer(CLIENT_ID + ":" + CLIENT_SECRET)).toString("base64");
var TOKEN = "token";

describe("StatelessGithubStrategy tests", function(){
  describe("Constructor", function(){
    it("should have required options 'clientId' and 'clientSecret'", function(){
      new Strategy({clientId: CLIENT_ID, clientSecret: CLIENT_SECRET});
    });
    it("should fail if 'clientId' is missing", function(){
      (function(){
        new Strategy({clientSecret: CLIENT_SECRET});
      }).should.throw();
    });
    it("should fail if 'clientSecret' is missing", function(){
      (function(){
        new Strategy({clientId: CLIENT_ID});
      }).should.throw();
    });
    it("should process both 'clientId' and 'clientID'", function(){
      var s = new Strategy({clientId: CLIENT_ID, clientSecret: CLIENT_SECRET});
      s.options.clientId.should.equal(CLIENT_ID);
      s = new Strategy({clientID: "clientID", clientSecret: CLIENT_SECRET});
      s.options.clientId.should.equal("clientID");
    });
    it("should have optional verify function", function(){
      var s = new Strategy({clientId: CLIENT_ID, clientSecret: CLIENT_SECRET, verify: function(){}});
      s.verify.should.be.a.function;
      s = new Strategy({clientId: CLIENT_ID, clientSecret: CLIENT_SECRET}, function(){});
      s.verify.should.be.a.function;
      s = new Strategy({clientId: CLIENT_ID, clientSecret: CLIENT_SECRET});
      (!!(s.verify)).should.be.false;
    });
    it("should assign 'name' of created instance", function(){
      var s = new Strategy({clientId: CLIENT_ID, clientSecret: CLIENT_SECRET});
      s.name.should.equal("stateless-github");
    });
  });

  describe("#authenticate", function(){
    var strategy, result;
    beforeEach(function(){
      result = null;
      strategy = new Strategy({clientId: CLIENT_ID, clientSecret: CLIENT_SECRET});
      strategy.fail = function(err){
        //console.error(err);
        throw err;
      };
      strategy.success = function(user){
        result = user;
      }
    });
    describe("without userName and password", function(){
      var stub;
      beforeEach(function(){
        stub = nock(Strategy.GITHUB)
          .get("/applications/" + CLIENT_ID + "/tokens/" + TOKEN)
          .matchHeader("authorization", "Basic " + CLIENT_TOKEN);
      });
      afterEach(function(){
        stub.done();
      });
      it("should fail if header 'authorization' is missing", function(){
        (function(){
          strategy.authenticate({});
        }).should.throw();
      });
      it("should return success if access token is valid", function(done){
        stub = stub.reply(200);
        strategy.success = function(user){
          user.token.should.equal(TOKEN);
          done();
        };
        strategy.authenticate({headers: {authorization: "Bearer token"}});
      });
      it("should fail if access token is invalid", function(done){
        stub = stub.reply(404);
        strategy.fail = function(){
            done();
        };
        strategy.success = function(){
          done("Expected error here");
        };
        strategy.authenticate({headers: {authorization: "Bearer token"}});
      });
      describe("with verify function", function(){
        var called;
        beforeEach(function(){
          called = false;
          strategy.verify = function(token, callback){
            token.should.equal(TOKEN);
            called = true;
            callback();
          };
        });
        it("should call verify function for accepted access token if need", function(done){
          stub = stub.reply(200);
          strategy.success = function(user){
            user.token.should.equal(TOKEN);
            called.should.be.true;
            done();
          };
          strategy.authenticate({headers: {authorization: "Bearer token"}});
        });
        it("should fail if verify returns error", function(done){
          stub = stub.reply(200);
          strategy.fail = function(){
            done();
          };
          strategy.success = function(){
            done("Expected error here");
          };
          strategy.verify = function(token, callback){
            callback(new Error("Something wrong here"));
          }
          strategy.authenticate({headers: {authorization: "Bearer token"}});
        });
        it("should fail and not call verify if token is invalid", function(done){
          stub = stub.reply(404);
          strategy.fail = function(){
            called.should.be.false;
            done();
          };
          strategy.success = function(){
            done("Expected error here");
          };

          strategy.authenticate({headers: {authorization: "Bearer token"}});
        });
      });
    });
  });
});