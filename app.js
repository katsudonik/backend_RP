const config = require('config');
var express = require('express');
var request = require('request');
var app = express();
const bodyParser = require('body-parser');

var scope = 'user';

var passport = require('passport');
app.use(passport.initialize());

app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

var server = app.listen(config.server.port, function() {
  console.log('Server is started');
});

if (process.env.NODE_ENV === 'development' || process.env.NODE_ENV === 'sp_development' || process.env.NODE_ENV === 'staging' || process.env.NODE_ENV === 'sp_staging') {
	app.use(function(req, res, next) {
	  res.header('Access-Control-Allow-Origin', '*');
	  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
	  next();
	});
}

app.post('/token', function(req, res, next) {
	console.log(req.body.login_id);

	matched = req.body.login_id.match(new RegExp(config.saml_pattern))
	if (matched != null) {
		return saml_init(req, res);
	}
	return normal_login(req, res);
});

app.post('/saml_init', function(req, res, next) {
	matched = req.body.login_id.match(new RegExp(config.saml_pattern))
	if (matched != null) {
		return saml_init(req, res);
	}
    return res.send({ result : true, status : '200', message : 'user is not saml user' , data : {}});
});

app.post('/saml_consume', function(req, res, next) {
	return saml_consume(req, res);
});


app.post('/saml_front_consumer', function(req, res, next) {
    return res.render('saml_front_consumer', {SAMLResponse: req.body.SAMLResponse});
});


app.post('/revoke', function(req, res, next) {
	return revoke_token(req, res);
});

function normal_login(req, res) {
  request({
    url: config.api.endpoint.token,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    form: {
      client_id: config.client.id,
      client_secret: config.client.secret,
      grant_type: 'password',
      login_id: req.body.login_id,
      password: req.body.password
    }
  }, function(error, response, body) {
	  return return_token(res, body);
  });
}

function saml_init(req, res) {
  request({
    url: config.api.endpoint.saml.init,
    method: 'GET',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  }, function(error, response, body) {
    var obj = JSON.parse(body);
    var redirectTo = obj['redirect_to'];
    if (!redirectTo){
      return res.send({ result : false, status : '404', message : 'saml init endpoint is not exist' });
    }
    return res.send({ result : true, status : '200', message : 'redirect to redirect_to endpoint' , data : {"redirect_to" : redirectTo} });
  });
}

function saml_consume(req, res) {
  request({
    url: config.api.endpoint.saml.consume,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    form: {
      SAMLResponse: req.body.SAMLResponse,
    }
  }, function(error, response, body) {
	  console.log(body);
	  return return_token(res, body);
  });
}

function revoke_token(req, res) {
  request({
    url: config.api.endpoint.revoke_token,
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    form: {
      client_id: config.client.id,
      client_secret: config.client.secret,
      grant_type: 'password',
      token: req.body.token
    }
  }, function(error, response, body) {
    var obj = JSON.parse(body);
    console.log(obj);
    return res.send({ result : true, status : '200', message : '' , data : {} });
  });
}

function return_token(res, body){
    var obj = JSON.parse(body);
    var accessToken = obj['access_token'];
    if (!accessToken){
      return res.send({ result : false, status : '401', message : 'authentication failed' });
    }
    return res.send({ result : true, status : '200', message : 'authentication succeeded' , data : {"access_token" : accessToken} });
}
