import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import redis from 'redis';
import { createConnection, MysqlError } from 'mysql';
import { genSalt, hash, compare } from 'bcrypt';
import dotenv from 'dotenv';
dotenv.config();

const redisClient = redis.createClient(6379, process.env['REDIS_HOST'], {
	password: process.env['REDIS_PWD'],
	db: process.env['REDIS_DB']
});

redisClient.on('connection', () => console.log('RedisClient connected'));
redisClient.on('error', (err) => console.log('RedisClient error', err));

var connection = createConnection({
	host: String(process.env['MYSQL_HOST']),
	port: +String(process.env['MYSQL_PORT']),
	database: String(process.env['MYSQL_DB']),
	user: String(process.env['MYSQL_USER']),
	password: String(process.env['MYSQL_PASSWORD'])
});

connection.connect((err: MysqlError) =>
	err
		? console.log('error connecting: ' + err.stack)
		: console.log('connected to mysql as id ' + connection.threadId)
);

connection.query(
	`SELECT 
		* 
	FROM information_schema.tables 
	WHERE 
		table_schema = '${String(process.env['MYSQL_DB'])}' AND 
		table_name = 'AUTH_USERS' 
	LIMIT 1;`,
	(error, results, fields) => {
		if (error) throw error;
		if ((results as any[]).length === 0) {
			connection.query(
				`CREATE TABLE auth.AUTH_USERS(
					id INT NOT NULL AUTO_INCREMENT,
					username VARCHAR(256) NOT NULL,
					password BINARY(60) NOT NULL,
					firstName VARCHAR(35),
					lastName VARCHAR(35),
					email VARCHAR(256) NOT NULL,
					birthday DATE,
					creationDate TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
					lastAccessDate TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
					active BOOLEAN DEFAULT TRUE,
					PRIMARY KEY (id)
				)`,
				(err, _, __) => {
					if (err) throw err;
				}
			);
		} else {
			console.log('Auth user table exists');
		}
	}
);

const app: Application = express();
app.use(express.json());

/*
1) Sign In User
	UI sends this information in a POST statement

	Username
	Password

	Sends Access Token for UI & User information
	or sends 2FA token-flag
*/
/*
1b) Verify 2FA
*/
/*
2) Register User
	UI sends this information in a PUT statement
	
	Username
	Password
	First Name
	Last Name
	Birthday
	Email
	Phone Number
	Address (Street 1, Street 2, City, State, Zip Code)

	Store this information in MYSQL database
*/
app.put('/user/register', cors, (req, res) => {});

/*
3) Update User
4) User 2FA & Recovery Codes

5) User Create Application
6) User Edit Application
7) User Delete Application
8) User Update Application Claims

8) Application User Login, and Redirect
9) Application Verify Auth Code, send Access Token
10) Application Verify/Refresh Access Token




*/

/*
// Generate an auth code and redirect to your app client's
// domain with the auth code
app.post('/code', (req, res) => {
	// Generate a string of 10 random digits
	const authCode = new Array(10)
		.fill(null)
		.map(() => Math.floor(Math.random() * 10))
		.join('');

	authCodes.add(authCode);

	// Normally this would be a `redirect_uri` parameter, but for
	// this example it is hard coded.
	res.redirect(`http://localhost:3000/oauth-callback.html?code=${authCode}`);
});

app.get('/', (req: Request, res: Response, next: NextFunction) => {
	res.send(redisClient.get('testing'));
});

app.get('/:key/:value', (req: Request, res: Response, next: NextFunction) => {
	let response = redisClient.set(req.params.key, req.params.value);
	console.log(response);
	res.send(response);
});

app.get('/:key', (req: Request, res: Response, next: NextFunction) => {
	let value = redisClient.get(req.params.key);
	console.log(value);
	res.send(value);
});


// signup route
  router.post("/signup", async (req, res) => {
    const body = req.body;

    if (!(body.email && body.password)) {
      return res.status(400).send({ error: "Data not formatted properly" });
    }

    // creating a new mongoose doc from user data
    const user = new User(body);
    // generate salt to hash password
    const salt = await bcrypt.genSalt(10);
    // now we set user password to hashed password
    user.password = await bcrypt.hash(user.password, salt);
    user.save().then((doc) => res.status(201).send(doc));
  });

  // login route
  router.post("/login", async (req, res) => {
    const body = req.body;
    const user = await User.findOne({ email: body.email });
    if (user) {
      // check user password with hashed password stored in the database
      const validPassword = await bcrypt.compare(body.password, user.password);
      if (validPassword) {
        res.status(200).json({ message: "Valid password" });
      } else {
        res.status(400).json({ error: "Invalid Password" });
      }
    } else {
      res.status(401).json({ error: "User does not exist" });
    }
  });

*/

const expressPort = process.env.EXPRESS_PORT || 5000;
app.listen(expressPort, () =>
	console.log(`Server running on port ${expressPort}`)
);
