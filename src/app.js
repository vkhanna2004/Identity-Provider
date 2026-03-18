import express from 'express';
import helmet from 'helmet';
import swaggerUi from 'swagger-ui-express';
import YAML from 'yamljs';

import authRoutes from './routes/authRoutes.js';
import userRoutes from './routes/userRoutes.js';
import errorHandler from './middlewares/errorHandler.js';

const swaggerDocument = YAML.load('./swagger.yaml');
const app = express();

app.use(helmet());
app.use(express.json());
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

app.use('/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'IdP Service is running' });
});

app.use(errorHandler)


export default app;