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

const conn = mysql.createConnection({
  host: config.get('db.host'),
  database: config.get('db.database'),
  user: config.get('db.user'),
  password: config.get('db.password')
})

function Authenticate(req, res, next){
	const token = req.get("Authorization")
	const sql =`
SELECT * FROM users
WHERE token = ?
	`
	conn.query(sql, [token],function(err, results, fields){
		if (results.length > 0){
			res.locals.userid = results[0].id
			next()
		}
		else {
			res.status(401).json({
				message: "respect my authoritah"
			})
		}
	})
}

// this was tested
app.get("/api/activities",Authenticate,function(req,res,next){
	//Show a list of all activities I am tracking, and links to their individual pages
	const sql = `select * from activities`

	conn.query(sql,function(err, results, fields){
		let info = {activities: results}
		res.json({info})
	})
})

// this was tested
app.post("/api/activities", Authenticate, function(req,res, next){
	//Create a new activity for me to track.
	const activities = req.body.name
	const id = res.locals.userid
	console.log(req.body)
	const sql =`INSERT INTO activities (name,userid) VALUES (?, ?)`
	conn.query(sql,[activities, id],function(err, results, fields){
		if(err){
			res.json("didnt work")
		}else{
			res.json({
			message:"activity inserted",
			id:results.insertid
		})	
		}
	})
})

app.get("/api/activities/:id", Authenticate, function(req,res,next) {
	//Show information about one activity I am tracking, and give me the data I have recorded for that activity.
	const id = req.params.id
	const sql = `
SELECT 
    a.name, u.username, s.date, s.completed
FROM
    activities a
        JOIN
    users u ON a.userid = u.id
        JOIN
    stats s
WHERE
    s.activityid = id;`

    conn.query(sql,function(err, results, fields){
    	let stuff = {activities: results}
    	res.json(stuff)
    })
	
})

// this was tested
app.put("/api/activities/:id", Authenticate, function(req,res,next){
	//Update one activity I am tracking, changing attributes such as name or type. Does not allow for changing tracked data.
	const id = req.params.id
	const name = req.body.name
	const sql = `update activities set name = ? where id = ?`
	conn.query(sql,[name,id], function(err, results, fields){
		if (err){
			res.json({message: "there was an error"})
		}
		else{
			res.json({message: "success"})
		}
		
	})
})

//this was tested
app.delete("/api/activities/:id", Authenticate, function(req,res, next){
	//Delete one activity I am tracking. This should remove tracked data for that activity as well.
	const id = req.params.id
	const sql = `
DELETE FROM activities 
WHERE
    id = ?`
	conn.query(sql, [id], function(err, results, fields){
		if (err){
			res.json({
				message:"ooops",
				err})
		}else {
		res.json("info deleted")
		}	
	})

})

// this was tested
app.post("/api/activities/:id/stats", Authenticate, function(req,res,next){
	//Add tracked data for a day. The data sent with this should include the day tracked. You can also override(replace) the data for a day already recorded.
	const id = req.params.id
	const timestamp = new Date()
	const completed = req.body.completed
	const sql = `insert into stats (completed, date, activityid) values (?, ?, ?)`

	conn.query(sql, [completed,timestamp, id], function(err, results, fields){
		if(err){
			res.json({
			message:"nope",
			err: err 
			})
		}
		else {
			res.json({
				message: "yay! you did a thing"
			})
		}
	})

})

app.delete("/api/stats/:id", Authenticate, function(req,res,next){
	//Remove tracked data for a day.
	const date = req.body.date
	const id = req.params.id
	const sql = `delete from stats where id = ? and date = ?`
	conn.query(sql, [date,id],function(err, results, fields){
		if (err){
			res.json("cant delete that")
		}
		else {
			res.json("deleted")
		}
	})
	
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
	const sql = ` INSERT INTO users (username, password, token) VALUES (?, ?, ?)`

	bcrypt.hash(password,10).then(function(hashedPword){
		conn.query(sql, [username,hashedPword, token],function(err, results, fields){
			res.json({
				message: "user succesfully created",
				token: token
			})
		})
	})
})


app.listen(3000, function(){
  console.log("App running on port 3000")
})
