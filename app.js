const express = require("express");
const mongoose = require("mongoose");
const ejs  = require("ejs");
const app = express();
const reload = require('reload');
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require('bcrypt');
const saltRounds = 10;
const cookieParser = require("cookie-parser");

require("dotenv").config();


//set view engine
app.set('view engine', 'ejs');
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(cookieParser());

//connect mongoose 
mongoose.connect("mongodb://localhost:27017/Login_auth");

//creating MongoDB scehema
const loginSchema = new mongoose.Schema({
    email:String,
    username : String,
    password : String
})

const User = new mongoose.model("User_Login_Data",loginSchema);

const superUserSchemea = new mongoose.Schema({
    superPower:loginSchema,
    role:String
})
const superUser = new mongoose.model("superUser", superUserSchemea);




//route config for login page
app.route("/login")
    .get((req,res) => {
        res.render("login");
    })
    .post(async (req,res) => {

       const formUsername = (req.body.username);
       const formPassowrd = (req.body.password);
        User.findOne({username:formUsername},async (err,user)=>{
            if(user){
                 bcrypt.compare(formPassowrd, user.password,async(err, result) => {
                    const foundResult = await result;
                    try{
                        if(foundResult === true){
                            jwt.sign({ AuthId: user._id }, process.env.JWT_SECRET_KEY, function(err, token) {
                                res.cookie("AuthToken",token);
                                res.redirect("/");
                            });
                            
                        }else{
                            res.send("incorrect password");
                        }
                    }
                    catch(e){
                        res.send(e);
                    }
                });            
            }else{
                res.send("usernot found! please enter correct username ");
            }
        })
    
    })

//route config for Resgiter page
app.route("/register")
    .get((req,res) => {
        res.render("register");
    })
    .post(async (req,res) => {
        const formUsername = (req.body.username);
        const formEmail = (req.body.email);
        const formPassowrd = (req.body.password);
       try{
        await  bcrypt.hash(formPassowrd, saltRounds, function(err, hash) {
            const newUser =  new User({
                email:formEmail,
                username : formUsername,
                password : hash
            })
            
            if(formUsername !== "" && formEmail !== "" && formPassowrd !="" ){
                 newUser.save((err) => {
                    if(err){
                        res.status(401).send("Error creating new user");
                    }else {
                        res.status(200).redirect("/login")
                    }
                })
            }else{
                res.status(401).send("please fill all the details");
            }
        });
       }catch(e){
        console.log(e);
       }
    })

//function to check token is valid

function TokenValidator(req,res,next){
    if(req.cookies.AuthToken){
         jwt.verify(req.cookies.AuthToken, process.env.JWT_SECRET_KEY , async(err, decoded) => {
            const userID = await(decoded.AuthId);
            User.findById(userID, (err,userDetails) =>{
                if(err){
                    alert("some error with checking your id with database!, please try again")
                    res.clearCookie('AuthToken');
                    res.redirect("/login");
                    return;
                }else{
                    if(userID === userDetails.id){
                        console.log("true")
                        next();
                    }else{
                        alert("some error with checking your id with database!, please try again")
                        res.clearCookie('AuthToken');
                        res.redirect("/login");
                        return;
                    }
                }
            } )
          });
    }else{
        res.redirect("/login");
    }
}


//route config for Home page
app.route("/")
    .get(TokenValidator,(req,res) => {
        res.render("home");

    })

//route config for auth page
app.route("/auth")
    .get((req,res) => {
        res.render("auth");
    })

//route config for addAdmin page
app.route("/addAdmin")
    .get(TokenValidator,(req,res) => {
        res.render("addAdmin");
    })
    .post((req,res) => {
       console.log(req.body.username);
    })


app.listen("3000",(req,res)=>{
    console.log("server listing on port 3000")
})

reload(app);