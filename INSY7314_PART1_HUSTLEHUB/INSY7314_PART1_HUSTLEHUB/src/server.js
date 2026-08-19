const fs = require('fs');
const https = require('https');
const path = require('path');
const app = require('./app');
const config = require('./config/env');

const keyPath = path.resolve(config.sslKeyPath);
const certPath = path.resolve(config.sslCertPath);

if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) {
  // eslint-disable-next-line no-console
  console.error(
    `SSL certificate not found at "${keyPath}" / "${certPath}".\n` +
    'Run "npm run gen-cert" to generate a local self-signed certificate before starting the server.\n' +
    'The POE requires the API to be served over HTTPS - this app will not fall back to plain HTTP.'
  );
  process.exit(1);
}

const httpsOptions = {
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath),
};

https.createServer(httpsOptions, app).listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`HustleHub+ API listening securely on https://localhost:${config.port}`);
  // eslint-disable-next-line no-console
  console.log(`Environment: ${config.nodeEnv}`);
});
