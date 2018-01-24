import http from 'http';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import config from './config.json';
import {exec} from 'shelljs';
import async from 'async';

const app = express();
app.server = http.createServer(app);

// logger
app.use(morgan('dev'));

// 3rd party middleware
app.use(cors({
  exposedHeaders: config.corsHeaders
}));

app.use(bodyParser.json({
  limit : config.bodyLimit
}));

app.server.listen(process.env.PORT || config.port, () => {
  console.log(`Started on port ${app.server.address().port}`);
});

function hasAll(string, strings) {
  return strings.filter(s => string.indexOf(s) > -1).length === strings.length;
}

function hasEither(string, strings) {
  return strings.filter(s => string.indexOf(s) > -1).length > 0;
}

function last(string, delimitier) {
  const parts = string.split(delimitier);
  return parts[parts.length - 1];
}

function head(string, delimitier) {
  const parts = string.split(delimitier);
  return parts[0];
}

function tail(string, delimitier) {
  const parts = string.split(delimitier);
  parts.shift();
  return parts;
}

function shell(command, cb) {
  exec(command, (code, stdout, stderr) => {
    if (code !== 0) {
      return cb({
        command: command,
        stderr: stderr
      });
    }

    cb(null, stdout);
  });
}

function parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, cb) {
  exec('netstat --tcp --listening --numeric --program | awk \'{print $4,$7}\'', (code, stdout, stderr) => {
    // if terraform command time out, no response is returned by express, why?
    if (code !== 0) {
      return cb({
        command: 'netstat',
        stderr: stderr
      });
    }

    const uniqueNetstatItems = (accumulator, currentValue) => {
      if (accumulator.findIndex(c => c.pid === currentValue.pid) < 0) {
        accumulator.push(currentValue);
      }
      return accumulator;
    };

    const processes = stdout
      .split('\n')
      .filter(i => hasAll(i,[':','/']) && hasEither(i,['0.0.0.0','127.0.0.1','::']) && i.split(' ').length === 2)
      .map(i => (i.indexOf('::') > -1 ? i.replace('::', '0.0.0.0') : i) ) //hacky, change later
      .map(i => {
        var socketAndProcess = i.split(' ');
        return {
          port: socketAndProcess[0].split(':')[1],
          pid: socketAndProcess[1].split('/')[0],
          program: socketAndProcess[1].split('/')[1]
        };
      })
      .filter(i => IGNORED_PORTS.indexOf(i.port) < 0 && IGNORED_PROGRAMS.indexOf(i.program) < 0)
      .reduce(uniqueNetstatItems, []);

    cb(null, {processes});
  });
}

app.get('/processes', (req, res) => {
  const IGNORED_PORTS = ['22','111', `${app.server.address().port}`];
  const IGNORED_PROGRAMS = ['rpc.statd'];

  parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, (err, processes) => {
    if (err) {
      return res.status(404).json(err);
    }
    res.json(processes);
  });
});

function parseProcfs(pid, cb) {
  let cmdline, exe, bin, entrypointCmd, entrypointArgs;

  async.series([
    function(callback) {
      shell(`cat /proc/${pid}/cmdline`, (err, stdout) => {
        if (err) {
          return callback(err);
        }

        cmdline = stdout;
        callback(null);
      });
    },
    function(callback) {
      shell(`readlink -f /proc/${pid}/exe`, (err, stdout) => {
        if (err) {
          return callback(err);
        }

        exe = stdout;
        bin = head(last(exe,'/'),'\n'); //strip new line here !!!
        callback(null);
      });
    },
    function(callback) {
      exec(`which ${bin}`, code => {
        if (code !== 0) {
          entrypointCmd = head(exe,'\n');
        } else {
          entrypointCmd = bin;
        }

        entrypointArgs = tail(cmdline,'\0').map(a => a.trim()).filter(a => a.length > 0);
        callback(null);
      });
    },
  ],
  function(err) {
    if (err) {
      return cb(err);
    }

    cb(null, {cmdline, exe, bin, entrypointCmd, entrypointArgs});
  });
}

app.get('/processMetadata/:pid', (req, res) => {
  parseProcfs(req.params.pid, (err, metadata) => {
    if (err) {
      return res.status(404).json(err);
    }
    res.json(metadata);
  });
});

app.get('/docs', (req, res) => {
  res.send('Hello world!');
});

export default app;