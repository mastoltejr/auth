import express, { Application, Request, Response, NextFunction } from 'express';
import dotenv from 'dotenv';
dotenv.config();
const app: Application = express();

app.use(express.static(__dirname + '/public/'));

app.get('/', (req: Request, res: Response, next: NextFunction) => {
	res.send('hello');
});

const expressPort = process.env.EXPRESS_PORT || 8000;
app.listen(expressPort, () =>
	console.log(`Server running on port ${expressPort}`)
);
