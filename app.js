//jshint esversion:6

//This web app allows users to register and submit one "secret" anonmously
//Backend is Express, Database is MongoDB
//Users may use Google to login or register directly
//Authentication uses Passport.js middleware 1)google-oauth20 2)passport-local 


require('dotenv').config(); //Environment Variables

const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
//const encrypt = require('mongoose-encryption');
//const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const port = 3000;

const app = express();

app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

//Config package - express-session
app.use(session({
  secret: 'Evergreen Pine Cone Fir Tree Conifer',
  resave: false,
  saveUninitialized: false,
}));

//Config package - passport
app.use(passport.initialize());
app.use(passport.session());


//Connect & Setup MongoDB________________________
mongoose.connect(process.env.MONGO_URI, {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema ({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

//Config package passport-local-mongoose & mongoose-findOrCreate
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Create User per schema
const User = new mongoose.model("User", userSchema);
//_______________End of Database Setup________________


//Config Passport
passport.use(User.createStrategy());

//Config Passport Sessions
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


//Configure Passport.js - Google OAuth
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets", //aka redirect URI in google dev console project
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo' //fix to remove Google+ query github #51
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate(
      { googleId: profile.id,
        username: profile.emails[0].value //storing google profile email as username
      },
      function (err, user) {
        return cb(err, user);
    });
  }
));


//HOME page
app.get("/", function(req, res){
  res.render("home");
});

//Google Button Sign In - Passport using Google Auth Strategy (see GitHub Readme passport-google-oauth2)

app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile", "email"] })
);

//Google Callback Route - must match what is in Google Dev Console ("Authrized redirect URLs")
app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });


//LOGIN Page
app.get("/login", function(req, res){
  res.render("login");
});

//Register Page
app.get("/register", function(req, res){
  res.render("register");
});

//Secrets Page - Anyone can see this page (logged in or not)
//Renders all User secrets that have been submitted
app.get("/secrets", function(req, res){
  User.find({"secret":{$ne:null}}, function(err, foundUsers){  // (find all secret feilds not null)
    if(err){console.log(err);}
    else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers}); //continued in secrets.ejs
      }
    }
  });
});

//Submit Secrets Route
app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
  } else{
    res.redirect("/login");
  }
});

//Post Submitted Secrets (POST request from button on submit page)
app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    } else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

//Logout Page
app.get("/logout", function(req, res){
  req.logout();
  res.redirect("/");
});


//Creating New User (referencing input "name" tags on HTML forms)
//Only render Secrets page is user is registered and logged in
//Using passport local strategy
app.post("/register", function(req, res){
  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
});

//Login Page - check user against the credentials they input
//Render Secrets page if login is successful
app.post('/login', passport.authenticate('local',
{
  successRedirect: '/secrets',
  failureRedirect: '/login'
}));


app.listen(port, () => {
  console.log(`Server started on port ${port}`);
});
