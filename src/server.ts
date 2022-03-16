import express, {
  Request,
  Response,
  NextFunction,
  Application as ExpressApplication,
  RequestHandler,
  application
} from 'express';
import cors from 'cors';
import { createClient } from 'redis';
import { genSalt, hash, compare } from 'bcrypt';
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
import {
  Application,
  ApplicationScopes,
  PrismaClient,
  User
} from '@prisma/client';
import { nanoid } from 'nanoid';
import { addHours, addSeconds } from 'date-fns';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { splitToken } from './util';

const prisma = new PrismaClient();
dotenv.config();

let redis = createClient({
  url: `redis://:${process.env['REDIS_PWD']}@${process.env['REDIS_HOST']}:6379/${process.env['REDIS_DB']}`
});

redis.on('connection', () => console.log('Redis is connected'));
redis.on('error', (err: any) => {
  console.log('Redis errored out', err);
  process.exit();
});

redis.connect();

const isProductionEnv = false;
const endpoint = isProductionEnv
  ? 'https://auth.stolte.us'
  : 'http://localhost:5001';

const app: ExpressApplication = express();

app.use(cors());
app.use(cookieParser());
app.use(express.json());
app.use(
  express.urlencoded({
    extended: true
  })
);
app.set('view engine', 'ejs');
app.set('views', join(__dirname, '/pages'));
app.use(express.static(__dirname + '/public'));

const cookieMiddleware: RequestHandler = async (req, res, next) => {
  const {
    accessToken: accessTokenBase,
    accessTokenSecret,
    refeshToken: refreshTokenBase,
    refreshTokenSecret
  } = req.cookies;
  const accessToken = accessTokenBase + '.' + accessTokenSecret;
  const refreshToken = refreshTokenBase + '.' + refreshTokenSecret;

  try {
    let value =
      (await redis.get(accessToken)) ?? (await redis.get(refreshToken));
    if (value === null) return res.status(401).send('Invalid or expired token');

    const [tokenType, clientId, applicationSecret] = value.split('|');

    await jwt.verify(
      tokenType === 'access' ? accessToken : refreshToken,
      tokenType === 'access'
        ? applicationSecret
        : String(process.env['AUTH_SECRET']),
      {
        issuer: process.env['AUTH_ISSUER'],
        audience: clientId,
        ignoreExpiration: req.route.path === '/oauth2/v1/logout',
        ignoreNotBefore: req.route.path === '/oauth2/v1/logout'
      },
      (error, payload) => {
        if (error !== null)
          return res
            .status(401)
            .send({ error: error.name, message: error.message });
        if (payload === undefined) return res.status(400).send('Invalid Token');
        const { user, clientId } = payload as TokenPayload;

        req.body['user'] = user;
        req.body['clientId'] = clientId;

        if (tokenType === 'refresh') {
          const newAccessToken = jwt.sign(payload, applicationSecret, {
            issuer: process.env['AUTH_ISSUER'],
            expiresIn: '1h',
            audience: clientId
          });

          const newAccessTokenSplit = splitToken(newAccessToken);

          redis.setEx(
            newAccessToken,
            3600,
            `access|${clientId}|${applicationSecret}`
          );
          redis.del(accessToken);

          const newRefreshToken = jwt.sign(
            payload,
            String(process.env['AUTH_SECRET']),
            {
              issuer: process.env['AUTH_ISSUER'],
              expiresIn: '6h',
              audience: clientId
            }
          );

          const newRefreshTokenSplit = splitToken(newRefreshToken);

          redis.setEx(
            newRefreshToken,
            3600 * 6,
            `refresh|${clientId}|${applicationSecret}`
          );
          redis.del(refreshToken);

          res
            .cookie('accessToken', newAccessTokenSplit[0], {
              sameSite: isProductionEnv,
              secure: isProductionEnv
            })
            .cookie('accessTokenSecret', newAccessTokenSplit[1], {
              httpOnly: isProductionEnv,
              sameSite: isProductionEnv,
              secure: isProductionEnv
            })
            .cookie('refreshToken', newRefreshTokenSplit[0], {
              sameSite: isProductionEnv,
              secure: isProductionEnv
            })
            .cookie('refreshTokenSecret', newRefreshTokenSplit[1], {
              httpOnly: isProductionEnv,
              sameSite: isProductionEnv,
              secure: isProductionEnv
            });
        }

        next();
      }
    );
  } catch {
    res.status(400).send('Could not connect to database');
  }
};

const limitToDevMiddleware: RequestHandler = (req, res, next) => {
  if (isProductionEnv)
    return res
      .send(400)
      .send('This route is only available in development environment');
  next();
};

const logger: RequestHandler = (req, res, next) => {
  console.log('================================');
  console.log(`${req.route.path}: ${new Date()}`);
  console.log(req.body);
  next();
};

type SlimUser = Partial<User> & {
  oid: User['oid'];
};

interface TokenPayload {
  clientId: string;
  user: SlimUser;
}

type CookieParsedRequest<T = {}> = Request & {
  body: TokenPayload & T;
  cookies: {
    accessToken: string;
    accessTokenSecret: string;
    refreshToken: string;
    refreshTokenSecret: string;
  };
};

app.post(
  '/initialize',
  limitToDevMiddleware,
  logger,
  async (req, res, next) => {
    const salt = await genSalt(10);
    const passwordHash = await hash(req.body.password, salt);
    const user = await prisma.user.create({
      data: {
        email: req.body.user,
        password: passwordHash,
        applications: {
          create: [{ displayName: 'Application Portal' }]
        }
      }
    });

    const scopeInfo = await prisma.applicationScopeInfo.createMany({
      data: [
        {
          scope: 'email_read',
          summary: 'Read your email address',
          description:
            'This app would like to have access to your email address as to display it when you log in for a better user experience.'
        },
        {
          scope: 'email_readwrite',
          summary: 'Read/Write your email address',
          description:
            'This app would like to have access to your email address as to display it for a better user experience. In addition this app would be able to update your email address should you provide it. The change will apply to all other applications utilizing Stolte SSO.'
        },
        {
          scope: 'email_notify',
          summary: 'Notify you via email',
          description: 'This app would like to email you notifications.'
        },
        {
          scope: 'name_read',
          summary: 'Read your name',
          description:
            'This app would like to have access to your name as to display it when you log in for a better user experience.'
        },
        {
          scope: 'name_readwrite',
          summary: 'Read/Write your name',
          description:
            'This app would like to have access to your name as to display it for a better user experience. In addition this app would be able to update your name should you provide it. The change will apply to all other applications utilizing Stolte SSO.'
        },
        {
          scope: 'phone_read',
          summary: 'Read your phone number',
          description:
            'This app would like to have access to your phone number as to display it when you log in for a better user experience.'
        },
        {
          scope: 'phone_readwrite',
          summary: 'Read/Write your phone number',
          description:
            'This app would like to have access to your phone number as to display it for a better user experience. In addition this app would be able to update your phone number should you provide it. The change will apply to all other applications utilizing Stolte SSO.'
        },
        {
          scope: 'phone_notify',
          summary: 'Notify you via text-message',
          description: 'This app would like to text you notifications.'
        },
        {
          scope: 'address_read',
          summary: 'Read your address',
          description:
            'This app would like to have access to your address as to display it when you log in for a better user experience.'
        },
        {
          scope: 'address_readwrite',
          summary: 'Read/Write your address',
          description:
            'This app would like to have access to your address as to display it for a better user experience. In addition this app would be able to update your address should you provide it. The change will apply to all other applications utilizing Stolte SSO.'
        },
        {
          scope: 'address_notify',
          summary: 'Notify you via mail',
          description:
            'This app would like to mail you something should needed.'
        },
        {
          scope: 'birthday_read',
          summary: 'Read your birthday',
          description:
            'This app would like to have access to your birthday as to display it when you log in for a better user experience.'
        },
        {
          scope: 'birthday_readwrite',
          summary: 'Read/Write your birthday',
          description:
            'This app would like to have access to your birthday as to display it for a better user experience. In addition this app would be able to update your birthday should you provide it. The change will apply to all other applications utilizing Stolte SSO.'
        },
        {
          scope: 'profile_read',
          summary:
            'Read your profile ( including name, email, phone number, address, and birthday )',
          description:
            'This app would like to have access to your profile as to display it when you log in for a better user experience.'
        },
        {
          scope: 'profile_readwrite',
          summary:
            'Read/Write your profile ( including name, email, phone number, address, and birthday )',
          description:
            'This app would like to have access to your profile as to display it for a better user experience. In addition this app would be able to update your profile should you provide it. The change will apply to all other applications utilizing Stolte SSO.'
        }
      ]
    });

    res.status(200).send(true);
  }
);

app.get('/', (req, res, next) => res.render('home'));

app.get(
  '/application',
  cookieMiddleware,
  logger,
  async (req: CookieParsedRequest, res) => {
    const { clientId } = req.query;
    const authTokenPayload: TokenPayload = req.body.authTokenPayload;

    let errors = {
      clientId: required(clientId)
    };

    if (anyErrors(errors)) {
      res.send(400).send(errors);
      return;
    }

    const app = await prisma.application.findFirst({
      where: {
        clientId: String(clientId),
        ownerId: authTokenPayload.user.oid
      }
    });

    if (app === null) {
      return res.status(400);
    }

    return res.status(200).send(app);
  }
);

app.get(
  '/applications',
  cookieMiddleware,
  logger,
  async (req: CookieParsedRequest, res) => {
    const authTokenPayload: TokenPayload = req.body.authTokenPayload;

    const apps = await prisma.application.findMany({
      where: {
        clientId: authTokenPayload.clientId,
        ownerId: authTokenPayload.user.oid
      }
    });

    return res.status(200).send(apps);
  }
);

app.put(
  '/application',
  cookieMiddleware,
  logger,
  async (req: CookieParsedRequest, res) => {
    const { displayName } = req.query;
    const authTokenPayload: TokenPayload = req.body.authTokenPayload;
    let errors = {
      displayName: required(displayName)
    };

    if (anyErrors(errors)) {
      res.status(400).send(errors);
      return;
    }

    const newApp = await prisma.application.create({
      data: {
        ownerId: authTokenPayload.user.oid,
        displayName: displayName as string
      }
    });
    res.status(201).send(newApp);
  }
);

interface ApplicationPostRequest extends Request {
  body: {
    application: Application;
    scopes: ApplicationScopes[];
    authTokenPayload: TokenPayload;
  };
}

app.post(
  '/application',
  cookieMiddleware,
  logger,
  async (req: ApplicationPostRequest, res) => {
    const { application, scopes } = req.body;
    const authTokenPayload: TokenPayload = req.body.authTokenPayload;

    const verifyApp = await prisma.application.findFirst({
      where: {
        clientId: application.clientId,
        ownerId: authTokenPayload.user.oid
      }
    });

    if (verifyApp === null) {
      return res.status(400);
    }

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
  }
);

app.get('/oauth2/v1/:clientId/:userCode/signup', logger, (req, res) =>
  res.render('signup', {
    query: {
      clientId: req.params.clientId,
      userCode: req.params.userCode
    },
    errors: {},
    values: {}
  })
);

app.post(
  '/oauth2/v1/:clientId/:userCode/signup',
  logger,
  async (req, res, next) => {
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
      query: {
        clientId: req.params.clientId,
        userCode: req.params.userCode
      },
      errors: {},
      values: { email: newUser.email }
    });
  }
);

app.get('/oauth2/v1/:clientId/:userCode/login', logger, (req, res) => {
  res.render('login', {
    query: {
      clientId: req.params.clientId,
      userCode: req.params.userCode
    },
    errors: {},
    values: {}
  });
});

app.post('/oauth2/v1/:clientId/:userCode/login', logger, async (req, res) => {
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
      query: { clientId, userCode },
      errors,
      values: { email }
    });
  }

  try {
    const value = await redis.get(userCode);
    if (value === null) return res.status(400).send('Login session expired');

    const validApplication = await prisma.application.findUnique({
      where: { clientId },
      include: {
        scopes: {
          include: {
            info: true
          }
        }
      }
    });

    if (validApplication === null || validApplication.active === false)
      return res.status(400).send('Not a valid Application');

    const matchedUser = await prisma.user.findUnique({
      where: {
        email
      },
      include: {
        scopes: {
          where: {
            clientId: validApplication.clientId
          }
        }
      }
    });

    await compare(
      password,
      matchedUser?.password ?? '',
      async function (err, success) {
        if (success) {
          // User has logged in already
          await redis.setEx(userCode, 600, matchedUser?.oid ?? '');

          const confirmedUser = matchedUser!;

          if (
            (confirmedUser.scopes.length === 0 &&
              validApplication.scopes.length > 0) ||
            validApplication.scopes
              .filter((s) => s.required)
              .some(
                (s) =>
                  confirmedUser.scopes.find((us) => us.scopeId === s.id)
                    ?.status !== true
              )
          ) {
            return res.render('applicationScopes', {
              query: {
                user: confirmedUser.email,
                scopes: validApplication.scopes,
                displayName: validApplication.displayName,
                description: validApplication.description,
                clientId: validApplication.clientId,
                userCode: userCode
              },
              values: {}
            });
          }

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

          await redis.setEx(`${userCode}-status`, 60, 'authorization_success');

          return res
            .status(200)
            .send('Authorization successful, awaiting login');
        } else {
          return res.render('login', {
            query: { clientId, userCode },
            errors: { password: 'Incorrect Password' },
            values: { email }
          });
        }
      }
    );
  } catch {
    return res.status(400).send('Could not set authorizaiton as successful');
  }
});

app.post(
  '/oauth2/v1/:clientId/:userCode/acceptScopes',
  logger,
  async (req, res) => {
    const { clientId, userCode } = req.params;
    let errors = {
      clientId: required(clientId),
      userCode: required(userCode)
    };

    if (anyErrors(errors)) {
      return res
        .status(400)
        .send('Application clientId or userCode was not provided');
    }

    const validApplication = await prisma.application.findUnique({
      where: { clientId },
      include: {
        scopes: {
          include: {
            info: true
          }
        }
      }
    });

    if (validApplication === null || validApplication.active === false)
      return res.status(400).send('Not a valid Application');

    try {
      const value = await redis.get(userCode);
      if (value === null) return res.status(400).send('Login session expired');

      const now = new Date();
      const matchedUser = await prisma.user.update({
        where: { oid: value },
        data: {
          lastAccess: now,
          scopes: {
            createMany: {
              data: validApplication.scopes.map((s) => ({
                clientId: validApplication.clientId,
                scopeId: s.id,
                status: true,
                updatedAt: now
              }))
            }
          }
        }
      });

      // TODO User has logged in already
      await redis.setEx(userCode, 600, matchedUser?.oid ?? '');
      await redis.setEx(`${userCode}-status`, 60, 'authorization_success');

      return res.status(200).send('Authorization successful, awaiting login');
    } catch {
      return res.status(400).send('Could not set authorizaiton as successful');
    }
  }
);

app.get('/oauth2/v1/:invitation/invite', logger, async (req, res) => {
  const { inviation } = req.params;

  try {
    const value = await redis.get(inviation);
    if (value === null) return res.status(200).send('Invitation is not valid');

    const [clientId, oid] = value.split('|');

    const application = prisma.application.findUnique({ where: { clientId } });
    if (application === null)
      return res.status(200).send('Application not found');

    const user = prisma.user.findUnique({ where: { oid } });

    return res.render('invite', {
      query: {
        user,
        clientId: req.params.clientId,
        userCode: req.params.userCode
      },
      errors: {},
      values: {}
    });
  } catch {
    return res.status(400).send('Invitation unsuccessfull');
  }
});

app.post(
  '/oauth2/v1/logout',
  cookieMiddleware,
  logger,
  async (req: CookieParsedRequest, res) => {
    const authTokenPayload: TokenPayload = req.body.authTokenPayload;
    redis.del(
      `${authTokenPayload.user.oid}|${authTokenPayload.clientId}|access`
    );
    redis.del(
      `${authTokenPayload.user.oid}|${authTokenPayload.clientId}|refresh`
    );
    res.status(200).send(true);
  }
);

app.post('/oauth2/v1/deviceCode', logger, async (req, res) => {
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
    userCodeSuccess = await redis
      .setEx(userCode, 600, clientId)
      .then(() => true)
      .catch(() => false);
    retries -= 1;
  }

  if (!userCodeSuccess) {
    return res.status(400).send('Could not create userCode');
  }

  let loginStatusSuccess = false;
  retries = 5;
  while (!loginStatusSuccess && retries > 0) {
    loginStatusSuccess = await redis
      .setEx(`${userCode}-status`, 600, 'authorization_pending')
      .then(() => true)
      .catch(() => false);
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
    deviceCodeSuccess = await redis
      .setEx(deviceCode, 600, userCode)
      .then(() => true)
      .catch(() => false);
    retries -= 1;
  }

  if (!deviceCodeSuccess) {
    return res.status(400).send('Could not create deviceCode');
  }

  return res.status(200).send({
    clientId,
    authEndpoint: `${endpoint}/oauth2/v1/${clientId}/${userCode}/login`,
    message: `Application verification successful. Please have the user login at ${endpoint}/oauth2/v1/${clientId}/${userCode}/login. Poll token endpoint every 20s.`,
    expiry: addSeconds(new Date(), 300),
    userCode,
    interval: 2000,
    deviceCode
  });
});

interface TokenRequest extends Request {
  body: { clientId: Application['clientId']; deviceCode?: string };
}

app.post('/oauth2/v1/token', logger, async (req: TokenRequest, res) => {
  const { clientId, deviceCode } = req.body;
  let errors = {
    clientId: required(clientId),
    deviceCode: required(deviceCode)
  };

  if (anyErrors(errors)) {
    return res.status(400).send(errors);
  }

  try {
    const userCode = await redis.get(String(deviceCode));
    if (userCode === null) return res.status(200).send('expired_token');

    await redis.get(`${userCode}-status`).then((value) => {
      if (value === null) res.status(200).send('expired_session');
    });

    const oid = redis.get(userCode);
    if (oid === null) {
      res.status(200).send('expired_token');
      return;
    }

    const user = await prisma.user.findUnique({
      where: { oid: String(oid) },
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
      return;
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
      { oid: user.oid }
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

      const accessToken = jwt.sign(
        { clientId, user: slimUser },
        applicationSecret,
        {
          issuer: process.env['AUTH_ISSUER'],
          expiresIn: '1h',
          audience: clientId
        }
      );

      const accessTokenSplit = splitToken(accessToken);

      redis.setEx(accessToken, 3600, `access|${clientId}|${applicationSecret}`);

      redis.setEx(
        `${slimUser.oid}|${clientId}|access`,
        3600 * 6,
        `${accessToken}`
      );

      const refreshToken = jwt.sign(
        { clientId, user: slimUser },
        String(process.env['AUTH_SECRET']),
        {
          issuer: process.env['AUTH_ISSUER'],
          expiresIn: '6h',
          audience: clientId
        }
      );

      const refreshTokenSplit = splitToken(refreshToken);

      redis.setEx(
        refreshToken,
        3600 * 6,
        `refresh|${clientId}|${applicationSecret}`
      );
      redis.del(String(deviceCode));

      redis.setEx(
        `${slimUser.oid}|${clientId}|refresh`,
        3600 * 6,
        `${refreshToken}`
      );

      const loginToken = jwt.sign({ user: slimUser }, applicationSecret, {
        issuer: process.env['AUTH_ISSUER'],
        expiresIn: '1h',
        audience: clientId
      });

      return res
        .cookie('accessToken', accessTokenSplit[0], {
          sameSite: isProductionEnv,
          secure: isProductionEnv
        })
        .cookie('accessTokenSecret', accessTokenSplit[1], {
          httpOnly: isProductionEnv,
          sameSite: isProductionEnv,
          secure: isProductionEnv
        })
        .cookie('refreshToken', refreshTokenSplit[0], {
          sameSite: isProductionEnv,
          secure: isProductionEnv
        })
        .cookie('refreshTokenSecret', refreshTokenSplit[1], {
          httpOnly: isProductionEnv,
          sameSite: isProductionEnv,
          secure: isProductionEnv
        })
        .status(200)
        .send({
          tokenType: 'Bearer',
          scopes: scopes.map((s) => s.scope),
          user: slimUser,
          expiryDate: addHours(new Date(), 1),
          loginToken,
          oid
        });
    }
  } catch {
    res.status(400).send('Could not fetch data');
  }
});

const expressPort = process.env.EXPRESS_PORT || 5000;
app.listen(expressPort, () =>
  console.log(`Server running on port ${expressPort}`)
);
