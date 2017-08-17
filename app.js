const express = require('express')
const app = express()
const path = require('path')
const mustacheExpress = require('mustache-express');
const bodyParser = require('body-parser')
const config = require('config')
const mysql = require("mysql")
const uuid = require('uuid')
const bcrypt = require("bcrypt")

app.use(bodyParser.urlencoded({extended:false}))
app.use(bodyParser.json())
app.engine('mustache', mustacheExpress())
app.set('views', './views')
app.set('view engine', 'mustache')
app.use(express.static(path.join(__dirname, 'static')))

// before you use this, make sure to update the default.json file in /config
const conn = mysql.createConnection({
  host: config.get('db.host'),
  database: config.get('db.database'),
  user: config.get('db.user'),
  password: config.get('db.password')
})

app.post("/token", function(req,res,next){
	const username = req.body.username
	const password = req.body.password 
	const sql = ` SELECT password FROM users WHERE username = ? `

	conn.query(sql, [username], function (err, results, field){
		const hashedPword = results[0].password

		bcrypt.compare(password, hashedPword).then (function(match){
			if (match){
				const token = uuid ()

				const tokenUpsql =`
					UPDATE users 
					SET token = ?
					WHERE username = ?
				`

				conn.query(tokenUpsql, [token, username], function(err, results, fields){
					res.json({
						token: token
					})
				})
				
			} else {
				res.status(401).json({
					message: "invalid username/password"
				})
			
			}
		})
	})
})


app.post("/register", function(req, res, next){
	const username = req.body.username
	const password = req.body.password 
	const token = uuid()
	const sql = ` INSERT INTO users (username, password) VALUES (?, ?, ?)`

	bcrypt.hash(password,10).then(function(hashedPword){
		conn.query(sql, [username,hashedPword, token],function(err, results, fields){
			res.json({
				message: "user succesfully created"
			})
		})
	})
})

app.get(
	"/", function(req, res, next){
  res.render("index", {appType:"Express"})
})

app.listen(3000, function(){
  console.log("App running on port 3000")
})
