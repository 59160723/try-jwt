const express = require('express')
const mongodb = require('mongodb')
const bcrypt = require('bcryptjs')

const jwt = require('jsonwebtoken')
const { port, jwtKey } = require('./config')

const auth = require('./auth')
const app = express()
    // const port = process.env.PORT
    // const MONGODB_URL = process.env.MONGODB_URL
    // const MongoClient = mongodb.MongoClient
    // const jwtKey = process.env.JWT_KEY
app.use(express.json())


app.post('/register', async(req, res) => {
    let name = req.body.name
    let email = req.body.email
    let studentId = req.body.studentId
    let encryptedPwd = await bcrypt.hash(req.body.password, 8)

    const o = {
        name: name,
        email: email,
        studentId: studentId,
        password: encryptedPwd
    }
    const client = await require('./db')


    const db = client.db('buu')
    const r = await db.collection('users')
        .insertOne(o)
        .catch((err) => {
            console.error(`Cannot insert data to users collection :${err}`)
            return
        })

    let result = {
        _id: o._id,
        name: o.name,
        email: o.email,
        studentId: o.studentId
    }
    res.status(201).json(o)

})
app.post('/sign-in', async(req, res) => {
    let email = req.body.email
    let password = req.body.password

    const client = await require('./db')
    let db = client.db('buu')
    let user = await db.collection('users')
        .findOne({ email: email })
        .catch((err) => {
            console.error(`Cannot find users with email :${email}`)
            res.status(500).json({ error: err })
            return

        })

    if (!user) {
        res.status(401).json({ error: `your given email has not been found ` })
        return
    }
    let passwordIsValid = await bcrypt.compare(password, user.password)
    if (!passwordIsValid) {
        res.status(401).json({ error: `Username.Password is not match` })
        return
    }

    let token = await jwt.sign({ email: user.email, id: user._id }, jwtKey, { expiresIn: 30 })
    res.status(200).json({ token: token })
})
app.get('/me', auth, async(req, res) => {

    let decoded = req.decoded
    const client = await require('./db')
    let db = client.db('buu')
    let user = await db.collection('users').findOne({ _id: mongodb.ObjectID(decoded.id) })
        .catch((err) => {
            console.error(`Cannot get user by id in /me ${err}`)
            res.status(500).send({ error: err })
        })
    if (!user) {
        res.status(401).json({ error: `User was not found` })
        return
    }
    delete user.password
    res.json(user)



})
app.put('/me', auth, async(req, res) => {
    let decoded = req.decoded
    console.log(decoded);

    let newEmail = req.body.email
    const client = await require('./db')
    let db = client.db('buu')
    let result = await db.collection('users').updateOne({ _id: mongodb.ObjectID(decoded.id) }, { $set: { email: newEmail } })
        .catch((err) => {
            console.error(`Cannot get user by id in /me ${err}`)
            res.status(500).send({ error: err })
        })
    res.sendStatus(204)

})

app.listen(port, () => {
    console.log(`Pokemon api started at port ${port}`)
})