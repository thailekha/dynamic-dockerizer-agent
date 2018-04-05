import { exec } from 'shelljs';
import async from 'async';

const VERBOSE = 2;
const DEBUG = VERBOSE >= 2;
const INFO = VERBOSE >= 1;

export const logger = {
  overview: function(msg, extraCondition = true) {
    if (extraCondition) {
      console.log(`===> OVERVIEW: ${msg}`); // eslint-disable-line
    }
  },
  info: function(msg, extraCondition = true) {
    if (INFO && extraCondition) {
      console.log(`===> INFO: ${msg}`); // eslint-disable-line
    }
  },
  debug: function(msg, extraCondition = true) {
    if (DEBUG && extraCondition) {
      console.log(`===> DEBUG: ${msg}`); // eslint-disable-line
    }
  }
};

export function hasAll(string, strings) {
  return strings.filter(s => string.indexOf(s) > -1).length === strings.length;
}

export function hasEither(string, strings) {
  return strings.filter(s => string.indexOf(s) > -1).length > 0;
}

export function last(string, delimitier) {
  const parts = string.split(delimitier);
  return parts[parts.length - 1];
}

export function head(string, delimitier) {
  const parts = string.split(delimitier);
  return parts[0];
}

export function tail(string, delimitier) {
  const parts = string.split(delimitier);
  parts.shift();
  return parts;
}

export function remove(str, toRemove) {
  var final = str;
  while (final.indexOf(toRemove) > -1) {
    final = final.replace(toRemove,'');
  }
  return final;
}

export function splitTrimFilter(str) {
  return str.split('\n').map(l => l.trim()).filter(l => l.length > 0);
}

export function shell(command, checkStderrForError = true, cb) {
  exec(command, {silent:true}, (code, stdout, stderr) => {
    logger.info(command);
    logger.debug(`stdout: ${stdout}`);
    logger.debug(`stderr: ${stderr}`);

    if (code !== 0 || (checkStderrForError && stderr)) {
      return cb({command, code, stderr});
    }

    cb(null, stdout);
  });
}

export function mkdir(paths, cb) {
  const pathsBuilders = paths.map(path => function(asyncCallback) {
    shell(`mkdir -p ${path}`, true, err => {
      if (err) {
        return asyncCallback(err);
      }

      asyncCallback(null);
    });
  });

  async.series(pathsBuilders, function(err) {
    if (err) {
      return cb(err);
    }

    cb(null);
  });
}

function setkeyv(keyv, progressKey, value, cb) {
  if (keyv && progressKey) {
    return keyv
      .set(progressKey, value)
      .then(() => cb(null));
  }
  cb(null);
}

export function injectSetkeyv(keyv, progressKey, asyncCallbacks) {
  if (keyv && progressKey) {
    const injected = [];
    asyncCallbacks.forEach((ac, index, all) => {
      const progress = Math.round(index * 100 / all.length);
      injected.push(function(callback) {
        setkeyv(keyv, progressKey, progress, callback);
      });
      injected.push(ac);
    });
    return injected;
  }
  return asyncCallbacks;
}