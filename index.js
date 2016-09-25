/*-------------------------------------------------- MODULES --------------------------------------------------*/

var express = require('express');
var path = require("path");
var pg = require("pg").native;
var bodyParser = require('body-parser');
var squel = require('squel');
var expressJWT = require('express-jwt');
var jwt = require('jsonwebtoken');
var bcrypt = require('bcrypt');


/*-------------------------------------------------- CONSTS --------------------------------------------------*/

const PORT = process.env.PORT || 5099;
const TOKEN_SECRET = "Set me in the env variables";
const SALT_ROUNDS = 10;
const CONNECTION_STRING = "postgres://localhost:5432/dreamlister";


/*-------------------------------------------------- MIDDLEWARE --------------------------------------------------*/

//Create the express app
var app = express();

//Relates to database connection, need to make database first...
var client = new pg.Client(CONNECTION_STRING);
client.connect();

//Body Parser setup
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));


/*-------------------------------------------------- RESTFUL API --------------------------------------------------*/

// Dream Lister Items

app.get('/items', expressJWT({secret:TOKEN_SECRET}), function(req, res){

  var username = getUserFromToken(req, res);

  var query = squel.select().from('items').where("username = ?", username).toString();

  client.query(query, function(error, result){
    if (error) {
      res.status(501).json({
        message: "Internal Error: " + error
      });
    } else {
      res.status(200).json({
        data: result.rows,
        message: "Retrieved User Items"
      });
    }
  });

});

app.get("/item/:id", expressJWT({secret:TOKEN_SECRET}), function(req, res){

  var username = getUserFromToken(req, res);
  var itemID = parseInt(req.params.id);

  var query = squel.select().from('items').where("username = ? AND item_id = ?", username, itemID).toString();

  client.query(query, function(error, result){
    if (error) {
      res.status(501).json({
        message: "Internal Error: " + error
      });
    } else {
      res.status(200).json({
        data: result.rows[0],
        message: "Retrieved User Item"
      });
    }
  });

});

app.put('/item/:id', expressJWT({secret:TOKEN_SECRET}), function(req, res){

  console.log("Post on /item");

  var username = getUserFromToken(req, res);
  var itemID = parseInt(req.params.id);
  var newFields = req.body.newFields; //Should be a JSON containing all of the fields required to update an item

  var query = squel.update().table('items').setFields(newFields).where("username = ? AND item_id = ?", username, itemID).toString();

  client.query(query, function(error, result){
    if (error) {
      console.log("\t - Query failure");
      res.status(501).json({
        message: "Internal Error: " + error
      });
    } else {
      console.log("\t - Query success");
      res.status(200).json({
        message: "Updated Item"
      });
    }
  });

});

app.delete("/item/:id", expressJWT({secret:TOKEN_SECRET}), function(req, res){

  var username = getUserFromToken(req, res);
  var itemID = parseInt(req.params.id);

  var query = squel.delete().from('items').where("username = ? AND item_id = ?", username, itemID).toString();

  client.query(query, function(error, result){
    if (error) {
      res.status(501).json({
        message: "Internal Error: " + error
      });
    } else {
      res.status(200).json({
        message: "Deleted Item: " + itemID
      });
    }
  });

});

app.post('/item', expressJWT({secret:TOKEN_SECRET}), function(req, res){

  var username = getUserFromToken(req, res);
  var newFields = req.body.newFields; //Should be a JSON containing the fields for the new item

  var query = squel.insert().into('items').setFields({
    "username": username
  }).setFields(newFields).toString();

  client.query(query, function(error, result){
    if (error) {
      res.status(501).json({
        message: "Internal Error: " + error
      });
    } else {
      res.status(201).json({
        message: "Created Item"
      });
    }
  });
});

// Authentication

//==> Login
app.put('/auth', function(req, res){
  console.log("Login");

  var query;

  var username = req.body.username;
  var password = req.body.password;

  if(!username || !password) return res.status(400).json({message: "Missing username or password"});

  query = squel.select().from("users").where("username = ?", username).toString();

  client.query(query, function(error, result){
    if (error) {
      res.status(500).json({
        message: 'Internal Error'
      });
    } else if (result.rowCount < 1){
      res.status(404).json({
        message: 'Username Not Found'
      });
    } else {
      bcrypt.compare(password, result.rows[0].password, function(err, match){
        if (match) {
          var userToken = jwt.sign({"username": username}, TOKEN_SECRET);
          res.status(200).json({
            data: userToken, //This user token should be stored client side and passed back to the server on authorized requests.
            message: 'Logged in successfully'
          });
        } else {
          res.status(401).json({
            message: 'Incorrect Password'
          });
        }
      });
    }
  });
});

//==> Register
app.post('/auth', function(req, res){
  console.log("Register");

  var query;

  var username = req.body.username;
  var password = req.body.password;
  var email = req.body.email;

  if(!username || !password || !email) return res.status(400).json({message: "Missing username or password or email"});

  //Check the username is not already in the database
  query = squel.select().from("users").where("username = ?", username).toString();

  client.query(query, function(error, result){
    if (error) {
      res.status(500).json({
        data: username,
        message: 'Internal Error'
      });
    } else if(result.rowCount > 0) {
      res.status(409).json({
        data: username,
        message: 'Username Exists'
      });
    } else {

      //Use bcrypt to automatically salt and hash passwords
      bcrypt.hash(password, SALT_ROUNDS, function(err, hash){
        if (err) {
          res.status(500).json({
            data: username,
            message: 'Internal Error'
          });
        } else {
          //Create the sql statement and insert the new user
          query = squel.insert().into("users")
                      .setFields({"username": username,
                      "password": hash,
                      "email": email
                      }).toString();

          client.query(query, function(error){
            if(error){
              res.status(500).json({
                data: username,
                message: 'Internal Error'
              });
            } else {
              var userToken = jwt.sign({"username": username}, TOKEN_SECRET);
              res.status(201).json({
                  data: userToken,
                  message: 'Success'
              });
            }
          });
        }
      });
    }
  });
});


/*-------------------------------------------------- HELPER METHODS --------------------------------------------------*/

//Given a request object, this function will return the user who made the request based on the JWT
var getUserFromToken = function(req, res){
  //Code from the express-jwt documentation
  if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
    var token = req.headers.authorization.split(' ')[1];
    var decodedToken = jwt.decode(token);
    return(decodedToken.username);
  } else {
    res.status(401).json({
      message: 'Bad Token'
    });
  }
};


/*-------------------------------------------------- START SERVICE --------------------------------------------------*/

app.listen(PORT, function() {
  console.log("Dream Lister API running on port: " + PORT);
});
