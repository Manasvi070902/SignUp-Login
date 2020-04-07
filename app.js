var express=require('express');
const mongoose = require('mongoose');
var bodyParser = require('body-parser');//for handling post request
var bcrypt = require('bcryptjs');//for password hashing
var flash=require('connect-flash');
var session = require('express-session')//needed for connect-flash to work
var passport=require('passport');
const { ensureAuthenticated } = require('./config/auth');

const app=express();

 //handling post requests
 var urlencodedParser = bodyParser.urlencoded({ extended: false });

//passport config
require('./config/passport')(passport);


//use modals
const MarioChar = require('./models/mariochar');

//EJS
app.set('view engine','ejs');

//body-parser
app.use(express.urlencoded({ extended: true }));

//Express-session
app.use(session({ 
    secret: 'secret',
    resave:true,
    saveUninitialized:true,
 }));
 

 //Passport Middleware
 app.use(passport.initialize());
app.use(passport.session());

//connect-flash
app.use(flash());

//global variables(to get different alerts)
app.use((req,res,next)=>{
    res.locals.success_msg=req.flash('success_msg');
    res.locals.error_msg=req.flash('error_msg');
    res.locals.error=req.flash('error');
    next();
})


//adding static files like css
app.use('/css',express.static('css'));

//connect to mongodb
mongoose.set('useUnifiedTopology', true);
mongoose.connect('mongodb://localhost/data',{ useNewUrlParser: true}).then(() => console.log('connected')).catch((err)=>console.log('err'));
    

//routing
app.get('/',function(req,res){
    res.render('welcome');
})
app.get('/dashboard',ensureAuthenticated,function(req,res){
    res.render('dashboard',{user:req.user});
})
app.get('/login',function(req,res){
    res.render('login');
})
app.get('/signup',function(req,res){
    res.render('signup');
})
app.post('/signup',urlencodedParser,function(req,res){
    console.log(req.body);
    const{username,email,password,password2} = req.body;
    let errors=[];

    //check required fields
    if(!username || !email || !password || !password2){
        errors.push({msg: 'Please fill in all field'});
    }

    if(password !== password2){
        errors.push({msg: 'Passwords do not match'});
    }
    //check password length
    if(password.length<6){
        errors.push({msg :'Password should be atleast of 6 characters. '})
    }
    if(errors.length>0){
         res.render('signup' ,{errors,username,email,password});
    }else{
        //valiadation passed
        MarioChar.findOne({email:email})
         .then(user => {
             if(user){
                 //user exists
                 errors.push({msg : 'Email is already registered.'})
                 res.render('signup' ,{errors,username,email,password,password2});
             }else{
                 const newUser = new MarioChar({
                     username,
                     email,
                     password,
                 });
                 
                 //Hash password
                 bcrypt.genSalt(10,(err,salt) => bcrypt.hash(newUser.password,salt,(err,hash)=>{
                     if(err) throw err;
                     //set password to hashed
                     newUser.password=hash;
                     //save user
                     newUser.save().then(user=>{
                         req.flash('success_msg','You are now registered and can log in.')
                         res.redirect('/login');
                     })
                     .catch(err => console.log(err));
                 }))
             }
         })
    }

});

//Login Handle Post
app.post('/login',(req,res,next)=>{
    passport.authenticate('local',{
        successRedirect:'/dashboard',
        failureRedirect:'/login',
        failureFlash:true,
    })(req,res,next);
});

//logout handle
app.get('/logout',(req,res)=>{
    req.logout();
    req.flash('success_msg','You are logged out.');
    res.redirect('/login');
})
 

app.listen(3000,console.log('Server started on port 3000.'));

