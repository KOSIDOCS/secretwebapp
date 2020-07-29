require('dotenv').config(); // always put it right at the top to be able to access our environment variable.
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
// const encrypt = require("mongoose-encryption");
// const md5 = require('md5'); // using md5 Hash function instead mongoose encryption.
const bcrypt = require("bcrypt"); // using instead of md5 for hashing and salting.
const saltRounds = 10;

const app = express();

const port = 3000;

// Testing our evironment variable.
// console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});


const userSchema = new mongoose.Schema({
    email: String,
    password: String
});


// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"]});

const User = new mongoose.model('User', userSchema);

app.get("/", function(req, res) {
    res.render("home");
});
   
   
app.get('/login', function(req, res) {

       res.render("login");
});
   
   
app.get('/register', function(req, res) {

       res.render("register");
});
   

app.post('/register', function(req, res) {

    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        // Store hash in your password DB.
        const newUser = new User({
            email: req.body.username,
            password: hash
        });
    
        newUser.save(function(err) {
            if (err) {
                console.log(err);
                
            }else {
                res.render("secrets");
            }
        });
    });

});


app.post("/login", function(req, res) {
    const userName = req.body.username;
    const password = req.body.password;

    User.findOne({email: userName}, function(err, foundUser) {
        if (err) {
            console.log(err);
            
        } else {
            if (foundUser) {
                // Load hash from your password DB.
              bcrypt.compare(password, foundUser.password, function(err, result) {
                // result == true
                if (result === true) {
                    res.render("secrets");
                }else {
                    console.log(err);
                }
              });
            }
        }
    });
});





app.listen(port, function() {
 console.log("Server started on port 3000.");
 
});
