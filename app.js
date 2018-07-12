const config = require('config');
var express = require('express');
var request = require('request');
var app = express();
const bodyParser = require('body-parser');

var scope = 'user';

var passport = require('passport');
app.use(passport.initialize());
var handlebars = require('express-handlebars');
app.engine('html', handlebars());
app.set('view engine', 'handlebars');
app.set('views', __dirname + '/');

app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

var server = app.listen(config.server.port, function() {
  console.log('Server is started');
});

app.post('/token', function(req, res, next) {
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
    var obj = JSON.parse(body);
    var accessToken = obj['access_token'];
    if (!accessToken){
      return res.send({ result : false, status : '401', message : 'authentication failed' });
    }
    return res.send({ result : true, status : '200', message : 'authentication succeeded' , data : {"access_token" : accessToken} });
  });
});

