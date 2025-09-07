const express = require('express')
const fs = require('fs')
const dotenv = require('dotenv')
const { MongoClient } = require('mongodb')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cookeiPercer = require('cookie-parser')
const crypto = require('crypto')
const nodemailer = require('nodemailer')
const cors =require('cors')


const app = express()
const port = 5000
dotenv.config()

app.use(express.json())
app.use(cookeiPercer())
app.use(cors())


const uri = process.env.DB
const client = new MongoClient(uri)
const usersCollection = client.db('bharat-vi').collection('user')

async function connectDB() {
    try {
        await client.connect()
        console.log("✅ MongoDB connected");
    } catch (err) {
        console.error("❌ MongoDB connection error:", err);
    }
}

connectDB()

//mail connection server

const transport = nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 587,
    secure: false,
    auth: {
        user: process.env.NODE_MILER_USER,
        pass: process.env.NODE_MILER_PASS
    }
})

app.get('/', (req, res) => {
    res.send('Hello World!')
})

//register
app.post('/authentication_app/signup/', async (req, res) => {
    const user = req.body
    const hasPassword = await bcrypt.hash(user.password, 10)
    const newUser = {
        email: user.email,
        password: hasPassword
    }
    const resualt = await usersCollection.insertOne(newUser)
    res.send(resualt)
})

//login
app.post('/authentication_app/signin/', async (req, res) => {
    const email = req.body.email
    const password = req.body.password
    const user = await usersCollection.findOne({ email })
    if (!user) {
        res.send('email not match')
    }

    const passwordMatch = await bcrypt.compare(password, user.password)

    if (!passwordMatch) {
        res.send('Password not match')
    }

    const token = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' })
    res.cookie('token', token)
    res.json('User ligin successfully')
})

//logout
app.post('/authentication_app/logout/', async (req, res) => {
    const token = req.cookies.token
    if (!token) {
        res.json('You have not access , Login and Try again1')
    }
    const decoded = await jwt.verify(token, process.env.JWT_SECRET)
    if (!decoded) {
        res.json('Login and Try again2')
    }
    const user = await usersCollection.findOne({ email: decoded.email })
    if (!user) {
        res.json('You have not access , Login and Try again3')
    }
    res.cookie("token", '')

    res.json('Logout successfully')
})

//profile
app.get('/authentication_app/user_profile/', async (req, res) => {
    const token = req.cookies.token
    if (!token) {
        res.json('Please Login and Try again')
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    if (!decoded) {
        res.json('Please Login and Try again')
    }
    const user = await usersCollection.findOne({ email: decoded.email })
    res.send(user)
})

let otpStore
//send otp
app.post('/authentication_app/resend_otp/', async (req, res) => {
    const token = req.cookies.token
    if (!token) {
        res.json('Please Login and Try again')
    }
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    if (!decoded) {
        res.json('Please Login and Try again')
    }
    const { email } = decoded

    const otp = crypto.randomInt(100000, 999999).toString()
    otpStore = otp

    try {
        await transport.sendMail({
            from: process.env.NODE_MILER_USER,
            to: email,
            subject: "Your OTP Code",
            text: `Your OTP is: ${otpStore}`,
        });

        res.json({ message: "OTP sent successfully", otp: otpStore }); // শুধু একবার response
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "OTP send failed", details: err.message });
    }
    // res.send(otpStore)

})


//verify otp
app.post('/authentication_app/verify_otp/', (req, res) => {
    const { email, otp } = req.body

    const token = req.cookies.token

    const decoded = jwt.verify(token, process.env.JWT_SECRET)

    const emailMatch = email === decoded.email
    if (!emailMatch) {
        res.json('please login and use gmail')
    }

    const matchOTP = otp === otpStore
    if (!matchOTP) {
        res.json('OTP not match')
    }

    res.send('OTP veriry successfully ')
})


app.get('/user', async (req, res) => {
    const resualt = await usersCollection.find().toArray()
    res.send(resualt)
})


app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
