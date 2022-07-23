const express = require("express");
const mongoose = require("mongoose");
const ejs  = require("ejs");
const app = express();
const reload = require('reload');
const bodyParser = require("body-parser");
const bcrypt = require('bcrypt');
const saltRounds = 10;


//set view engine
app.set('view engine', 'ejs');
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())

//connect mongoose 
mongoose.connect("mongodb://localhost:27017/Login_auth");

//creating MongoDB scehema
const loginSchema = new mongoose.Schema({
    email:String,
    username : String,
    password : String
})

const User = new mongoose.model("User_Login_Data",loginSchema);





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
                    if(foundResult === true){
                        res.redirect("/");
                    }else{
                        res.send("incorrect password");
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

//route config for Home page
app.route("/")
    .get((req,res) => {
        res.render("home");
    })

//route config for auth page
app.route("/auth")
    .get((req,res) => {
        res.render("auth");
    })


app.listen("3000",(req,res)=>{
    console.log("server listing on port 3000")
})

reload(app);