import express, {
  Request,
  Response,
  NextFunction,
  Application as ExpressApplication,
  RequestHandler
} from 'express';
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
import { isApplicationScope } from './typeValidation';
import {
  Application,
  ApplicationScopes,
  PrismaClient,
  ScopeType,
  User
} from '@prisma/client';
import { stringArray } from './util';
import { nanoid } from 'nanoid';
import { addHours, addSeconds } from 'date-fns';
import jwt from 'jsonwebtoken';
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

const app: ExpressApplication = express();

app.use(
  express.urlencoded({
    extended: true
  })
);
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', join(__dirname, '/pages'));
app.use(express.static(__dirname + '/public'));

const tokenMiddleware: RequestHandler = async (req, res, next) => {
  const [authType, bearerToken] = String(req.headers['authorization']).split(
    ' '
  );
  if (authType !== 'Bearer')
    return res.status(401).send('Auth Token must be a Bearer Token');
  await redis.get(bearerToken, async (error, value) => {
    if (error || value === null)
      return res.status(401).send('Invalid or expired Token');
    const [tokenType, clientId, applicationSecret] = value.split('|');

    await jwt.verify(
      bearerToken,
      tokenType === 'access'
        ? applicationSecret
        : String(process.env['AUTH_SECRET']),
      {
        issuer: process.env['AUTH_ISSUER'],
        audience: clientId
      },
      (error, payload) => {
        if (error !== null)
          return res
            .status(401)
            .send({ error: error.name, message: error.message });
        if (payload === undefined) return res.status(400).send('Invalid Token');

        req.body['authTokenPayload'] = payload;
        next();
      }
    );
  });
};

app.post('/tokenTest', tokenMiddleware, (req, res) => {
  res.status(200).send(req.body);
});

app.get('/', (req, res, next) => res.render('home'));

//TODO verify token middleware
app.get('/application', async (req, res) => {
  const { clientId } = req.query;

  let errors = {
    clientId: required(clientId)
  };

  if (anyErrors(errors)) {
    res.send(400).send(errors);
    return;
  }

  const app = await prisma.application.findUnique({
    where: {
      clientId: String(clientId)
    }
  });

  return res.status(201).send(app);
});

//TODO verify token middleware
app.put('/application', async (req, res) => {
  const { ownerId, displayName } = req.query;

  let errors = {
    ownerId: required(ownerId),
    displayName: required(displayName)
  };

  if (anyErrors(errors)) {
    res.status(400).send(errors);
    return;
  }

  const newApp = await prisma.application.create({
    data: { ownerId: +ownerId!, displayName: displayName as string }
  });
  res.status(201).send(newApp);
});

//TODO verify token middleware
// ownerId must be owner of clientId

interface ApplicationPostRequest extends Request {
  body: { application: Application; scopes: ApplicationScopes[] };
}

app.post('/application', async (req: ApplicationPostRequest, res) => {
  const { application, scopes } = req.body;

  const { create, update } = scopes.reduce<{
    create: ApplicationScopes[];
    update: ApplicationScopes[];
  }>(
    ({ create, update }, s) => {
      if (!!s.id) return { create, update: [...update, s] };
      return { create: [...create, s], update };
    },
    { create: [], update: [] }
  );

  const app = await prisma.application.update({
    where: {
      clientId: application.clientId
    },
    data: {
      ...application,
      scopes: {
        deleteMany: {
          clientId: application.clientId,
          NOT: update.map(({ id }) => ({ id }))
        },
        ...(create.length > 0 && {
          createMany: {
            data: create
          }
        }),
        ...(update.length > 0 && {
          updateMany: update.map((s) => ({
            where: { id: s.id },
            data: s
          }))
        })
      }
    }
  });

  return res.status(200).send(app);
});

app.get('/oauth2/v1/:clientId/:userCode/login', (req, res) => {
  res.render('login', {
    query: {
      clientId: req.params.clientId,
      userCode: req.params.userCode
    },
    errors: {},
    values: {}
  });
});

app.post('/oauth2/v1/:clientId/:userCode/login', async (req, res) => {
  const { email, password } = req.body;
  const { clientId, userCode } = req.params;
  let errors = {
    email: combine(email, required, isEmail),
    password: required(password),
    clientId: required(clientId),
    userCode: required(userCode)
  };

  if (anyErrors(errors)) {
    if (errors.clientId !== undefined || errors.userCode !== undefined) {
      return res
        .status(400)
        .send('Application clientId or userCode was not provided');
    }
    return res.render('login', {
      query: { clientId },
      errors,
      values: { email }
    });
  }

  await redis.get(userCode, async (error, value) => {
    if (error) return res.status(400).send('Error connecting to Auth Server');
    if (value === null) return res.status(400).send('Login session expired');
  });

  const validApplication = await prisma.application.findUnique({
    where: { clientId }
  });
  if (!!!validApplication || validApplication.active === false)
    return res.status(400).send('Not a valid Application');

  const matchedUser = await prisma.user.findUnique({
    where: {
      email
    }
  });

  await compare(
    password,
    matchedUser?.password ?? '',
    async function (err, success) {
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
        redis.setex(userCode, 60, matchedUser?.uuid ?? '', (error, value) => {
          if (error) {
            return res
              .status(400)
              .send('Could not set authorizaiton as successful');
          }
          redis.setex(
            `${userCode}-status`,
            60,
            'authorization_success',
            (error, value) => {
              if (error) {
                return res
                  .status(400)
                  .send('Could not set authorizaiton as successful');
              }

              return res
                .status(200)
                .send('Authorization successful, awaiting login');
            }
          );
        });
      } else {
        return res.render('login', {
          query: { clientId },
          errors: { password: 'Incorrect Password' },
          values: { email }
        });
      }
    }
  );
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

  res.render('login', {
    query: {},
    errors: {},
    values: { email: newUser.email }
  });
});

app.post('/oauth2/v1/deviceCode', async (req, res) => {
  const { clientId } = req.body;
  let errors = {
    clientId: required(clientId)
  };

  if (anyErrors(errors)) {
    return res.status(400).send(errors);
  }

  const application = await prisma.application.findUnique({
    where: { clientId },
    include: {
      scopes: true
    }
  });

  if (application === null) {
    return res.status(400).send('Application not found');
  }

  let userCode: string = '';
  let userCodeSuccess = false;
  let retries = 5;
  while (!userCodeSuccess && retries > 0) {
    userCode = nanoid(12);
    userCodeSuccess = await redis.setex(userCode, 600, clientId);
    retries -= 1;
  }

  if (!userCodeSuccess) {
    return res.status(400).send('Could not create userCode');
  }

  let loginStatusSuccess = false;
  retries = 5;
  while (!loginStatusSuccess && retries > 0) {
    loginStatusSuccess = await redis.setex(
      `${userCode}-status`,
      600,
      'authorization_pending'
    );
    retries -= 1;
  }

  if (!loginStatusSuccess) {
    return res.status(400).send('Could not create loginStatus');
  }

  let deviceCode: string = '';
  let deviceCodeSuccess = false;
  retries = 5;
  while (!deviceCodeSuccess && retries > 0) {
    deviceCode = nanoid(69);
    deviceCodeSuccess = await redis.setex(deviceCode, 600, userCode);
    retries -= 1;
  }

  if (!deviceCodeSuccess) {
    return res.status(400).send('Could not create deviceCode');
  }

  return res.status(200).send({
    clientId,
    authEndpoint: `http://localhost:5001/oauth2/v1/${clientId}/${userCode}/login`,
    message: `Application verification successful. Please have the user login at http://localhost:5001/oauth2/v1/${clientId}/${userCode}/login. Poll token endpoint every 20s.`,
    expiry: addSeconds(new Date(), 300),
    userCode,
    interval: 20,
    deviceCode
  });
});

interface TokenRequest extends Request {
  body: { clientId: Application['clientId']; deviceCode?: string };
}

type SlimUser = Partial<User> & {
  oid: User['uuid'];
};

interface TokenPayload extends SlimUser {
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

app.post('/oauth2/v1/token', async (req: TokenRequest, res) => {
  const { clientId, deviceCode } = req.body;
  let errors = {
    clientId: required(clientId),
    deviceCode: required(deviceCode)
  };

  if (anyErrors(errors)) {
    return res.status(400).send(errors);
  }

  redis.get(String(deviceCode), async (error, userCode) => {
    if (error) return res.status(400).send('Could not fetch data');

    if (!!!userCode) return res.status(200).send('expired_token');

    redis.get(`${userCode}-status`, async (error, status) => {
      if (error) return res.status(400).send('Could not fetch data');
      if (!!!status) {
        return res.status(200).send('expired_session');
      } else if (status !== 'authorization_success') {
        return res.status(200).send(status);
      }

      redis.get(userCode, async (error, oid) => {
        if (error) return res.status(400).send('Could not fetch data');

        const user = await prisma.user.findUnique({
          where: { uuid: String(oid) },
          include: {
            scopes: {
              where: {
                clientId,
                status: true
              },
              select: {
                applicationScope: {
                  select: {
                    id: true,
                    scope: true
                  }
                }
              }
            }
          }
        });

        if (!!!user) {
          return res.status(200).send('expired_token');
        }

        const slimUser = user?.scopes.reduce<SlimUser>(
          (obj, s) => {
            const base = s.applicationScope.scope.substring(
              0,
              s.applicationScope.scope.indexOf('_')
            );
            switch (base) {
              case 'email':
                obj['email'] = user.email;
                break;
              case 'name':
                obj['firstName'] = user.firstName;
                obj['lastName'] = user.lastName;
                break;
              case 'phone':
                obj['phone'] = user.phone;
                break;
              case 'address':
                obj['address'] = user.address;
                obj['address2'] = user.address2;
                obj['city'] = user.city;
                obj['state'] = user.state;
                obj['zip'] = user.zip;
                break;
              case 'birthday':
                obj['birthday'] = user.birthday;
                break;
              case 'profile':
                obj['email'] = user.email;
                obj['firstName'] = user.firstName;
                obj['lastName'] = user.lastName;
                obj['phone'] = user.phone;
                obj['address'] = user.address;
                obj['address2'] = user.address2;
                obj['city'] = user.city;
                obj['state'] = user.state;
                obj['zip'] = user.zip;
                obj['birthday'] = user.birthday;
                obj['avatar'] = user.avatar;
                break;
              default:
                break;
            }
            return obj;
          },
          { oid: user.uuid }
        );

        const application = await prisma.application.findUnique({
          where: { clientId },
          select: {
            applicationSecret: true,
            objectId: true,
            scopes: true
          }
        });
        if (!!application) {
          const { applicationSecret, scopes } = application;

          const accessToken = jwt.sign(slimUser, applicationSecret, {
            issuer: process.env['AUTH_ISSUER'],
            expiresIn: '1h',
            audience: clientId
          });

          redis.setex(
            accessToken,
            3600,
            `access|${clientId}|${applicationSecret}`
          );

          const refreshToken = jwt.sign(
            slimUser,
            String(process.env['AUTH_SECRET']),
            {
              issuer: process.env['AUTH_ISSUER'],
              expiresIn: '6h',
              audience: clientId
            }
          );

          redis.setex(
            refreshToken,
            3600 * 6,
            `refresh|${clientId}|${applicationSecret}`
          );
          redis.del(String(deviceCode));

          return res.status(200).send({
            tokenType: 'Bearer',
            scopes: scopes.map((s) => s.scope),
            expiryDate: addHours(new Date(), 1),
            oid,
            accessToken,
            refreshToken
          });
        }
      });
    });
  });
});

interface RefreshRequest extends Request {
  body: { clientId: string; refreshToken: string };
}

app.post('/oauth2/v1/refresh', async (req: RefreshRequest, res) => {
  const { refreshToken } = req.body;

  let errors = {
    refreshToken: required(refreshToken)
  };

  if (anyErrors(errors)) {
    return res.status(400).send(errors);
  }

  redis.get(refreshToken, async (error, value) => {
    if (error) return res.status(400).send('Could not fetch data');
    if (value === null) return res.status(200).send('Token has been revoked');
    const [tokenType, clientId, applicationSecret] = value.split('|');

    if (tokenType !== 'refresh')
      return res.status(400).send('Not a refresh token');

    jwt.verify(
      refreshToken,
      String(process.env['AUTH_SECRET']),
      {
        issuer: process.env['AUTH_ISSUER'],
        audience: clientId
      },
      async (error, payload) => {
        if (error !== null)
          return res
            .status(401)
            .send({ error: error.name, message: error.message });
        if (payload === undefined) return res.status(400).send('Invalid Token');
        const body = payload as TokenPayload;
        if (body.aud !== clientId)
          return res.status(400).send('Incorrect Application');

        const application = await prisma.application.findUnique({
          where: { clientId },
          include: { scopes: true }
        });

        const newAccessToken = jwt.sign(body, applicationSecret, {
          issuer: process.env['AUTH_ISSUER'],
          expiresIn: '1h',
          audience: clientId
        });

        redis.setex(
          newAccessToken,
          3600,
          `access|${clientId}|${applicationSecret}`
        );

        const newRefreshToken = jwt.sign(
          body,
          String(process.env['AUTH_SECRET']),
          {
            issuer: process.env['AUTH_ISSUER'],
            expiresIn: '6h',
            audience: clientId
          }
        );

        redis.setex(
          newRefreshToken,
          3600 * 6,
          `refresh|${clientId}|${applicationSecret}`
        );
        redis.del(refreshToken);

        return res.status(200).send({
          tokenType: 'Bearer',
          scopes: application!.scopes.map((s) => s.scope),
          expiryDate: addHours(new Date(), 1),
          oid: body.uuid,
          accessToken: newAccessToken,
          refreshToken: newRefreshToken
        });
      }
    );
  });
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
