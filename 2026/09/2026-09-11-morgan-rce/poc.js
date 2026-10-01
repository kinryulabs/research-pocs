const http = require('http');
const morgan = require('morgan');

const lines = [];
const logger = morgan('combined', {
  stream: { write: (s) => lines.push(s) },
});

const server = http.createServer((req, res) => {
  logger(req, res, () => {
    res.statusCode = 200;
    res.end('ok');
  });
});

// The User-Agent closes its quoted field early and appends forged fields.
const payload = 'x" 200 999 "http://forged.example" "y';

server.listen(0, '127.0.0.1', () => {
  const { port } = server.address();
  const req = http.request(
    {
      host: '127.0.0.1',
      port,
      path: '/',
      method: 'GET',
      headers: { 'User-Agent': payload },
      agent: false,
    },
    (res) => {
      res.resume();
      res.on('end', () => {
        // Give morgan a tick to write the log line after the response finishes.
        setTimeout(() => {
          server.close();
          const line = lines.join('');
          // Vulnerable: the raw quote survives, so the line contains `x" 200 999`.
          // Patched: the quote is escaped (`x\" 200 999`), so this substring is absent.
          if (line.includes('x" 200 999 "http://forged.example" "y')) {
            console.log(process.env.POC_CANARY);
          }
          process.exit(0);
        }, 200);
      });
    }
  );
  req.on('error', () => {
    server.close();
    process.exit(1);
  });
  req.end();
});