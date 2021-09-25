import express, { Application, Request, Response, NextFunction } from 'express';
import redis from 'redis';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();
const app: Application = express();
const redisClient = redis.createClient(6379, '127.0.0.1');

redisClient.on('error', (err) => console.log('RedisClient error', err));

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

const expressPort = process.env.EXPRESS_PORT || 5000;
app.listen(expressPort, () =>
	console.log(`Server running on port ${expressPort}`)
);
