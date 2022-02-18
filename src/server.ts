import express, { Application, Request, Response, NextFunction } from 'express';
import cors from 'cors';
import { createClient, RedisClient } from 'redis';
import { genSalt, hash, compare } from 'bcrypt';
import { promisify } from 'util';
import dotenv from 'dotenv';
import { join } from 'path';
import {
  combine,
  isEmail,
  anyErrors,
  isUnique,
  matching,
  required,
  strongPassword
} from './validation';
import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();
dotenv.config();

let redis: RedisClient;

redis = createClient(6379, process.env['REDIS_HOST'], {
  password: process.env['REDIS_PWD'],
  db: process.env['REDIS_DB']
});

redis.on('connection', () => console.log('Redis is connected'));
redis.on('error', (err) => {
  console.log('Redis errored out', err);
  process.exit();
});

const asyncMiddleware =
  (fn: (req: Request, res: Response, next: NextFunction) => Promise<any>) =>
  (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };

const app: Application = express();

app.use(
  express.urlencoded({
    extended: true
  })
);
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', join(__dirname, '/pages'));
app.use(express.static(__dirname + '/public'));

app.get('/', (req, res) => res.render('home'));

app.post('/application', async (req, res) => {
  const {
    id,
    clientId,
    objectId,
    applicationSecret,
    ownerId,
    displayName,
    inviteOnly,
    applicationUrl,
    active,
    ...application
  } = req.body;

  let errors = {
    // email: combine(email, required, isEmail),
    // password: required(password)
  };
});

//TODO verify token middleware
app.put('/application', async (req, res) => {
  const { ownerId, displayName } = req.query;

  let errors = {
    ownerId: required(ownerId),
    displayName: required(displayName)
  };

  if (anyErrors(errors)) {
    res.send(400).send(errors);
    return;
  }

  const newApp = await prisma.application.create({
    data: { ownerId: +ownerId!, displayName: displayName as string }
  });
  res.status(201).send(newApp);
});

app.get('/user/login', (req, res) => {
  let og = req.query.scope ?? [];
  const scope = Array.isArray(og) ? (og as string[]) : [String(og)];

  res.render('login', {
    query: {
      clientId: req.query.clientId ?? '',
      scope: scope.join(','),
      invitation: req.query.invitation ?? ''
    },
    errors: {},
    values: {}
  });
});

app.post('/user/login', async (req, res) => {
  const { email, password } = req.body;
  let errors = {
    email: combine(email, required, isEmail),
    password: required(password)
  };

  if (anyErrors(errors)) {
    return res.render('login', { errors, values: { email } });
  }

  const matchedUser = await prisma.user.findUnique({
    where: {
      email
    }
  });

  await compare(password, matchedUser?.password ?? '', function (err, success) {
    if (success) {
      // TODO send to application url with correct password
      const now = new Date();
      matchedUser!.lastAccess = now;
      prisma.user.update({
        where: {
          id: matchedUser?.id
        },
        data: {
          lastAccess: now
        }
      });
      return res.status(200).send(matchedUser);
    } else {
      return res.render('login', {
        errors: { password: 'Incorrect Password' },
        values: { email }
      });
    }
  });
});

app.get('/user/signup', (req, res) =>
  res.render('signup', { errors: {}, values: {} })
);
app.post('/user/signup', async (req, res, next) => {
  const { email, password, password2 } = req.body;
  let errors = {
    email: combine(email, required, isEmail),
    password: combine(password, required, strongPassword),
    password2: matching(password, password2)
  };

  if (anyErrors(errors)) {
    return res.render('signup', { errors, values: { email } });
  }

  const matchedUser = await prisma.user.findUnique({
    where: {
      email
    }
  });

  if (!!matchedUser) {
    return res.status(400).send({
      email: isUnique(email, [matchedUser.email])
    });
  }

  const salt = await genSalt(10);
  const passwordHash = await hash(password, salt);

  const newUser = await prisma.user.create({
    data: {
      email,
      password: passwordHash
    }
  });

  res.render('login', { errors: {}, values: { email: newUser.email } });
});

app.post('/oauth2/v1/deviceCode', async (req, res) => {
  const { clientId, scope } = req.body;
  let errors = {
    clientId: required(clientId),
    scope: required(scope)
  };

  if (anyErrors(errors)) {
    return res.status(400).send(errors);
  }
});

const expressPort = process.env.EXPRESS_PORT || 5000;
app.listen(expressPort, () =>
  console.log(`Server running on port ${expressPort}`)
);

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
	First Name?
	Last Name?
	Birthday?
	Email
	Phone Number?
	Address? (Street 1, Street 2, City, State, Zip Code)

	Store this information in MYSQL database
*/

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
