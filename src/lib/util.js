import { exec } from 'shelljs';
import async from 'async';

const VERBOSE = 2;
const DEBUG = VERBOSE >= 2;
const INFO = VERBOSE >= 1;

/**	Creates a callback that proxies node callback style arguments to an Express Response object.
 *	@param {express.Response} res	Express HTTP Response
 *	@param {number} [status=200]	Status code to send on success
 *
 *	@example
 *		list(req, res) {
 *			collection.find({}, toRes(res));
 *		}
 */
export function toRes(res, status=200) {
  return (err, thing) => {
    if (err) {
      return res.status(500).send(err);
    }

    if (thing && typeof thing.toObject==='function') {
      thing = thing.toObject();
    }
    res.status(status).json(thing);
  };
}

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

export function shell(command, cb) {
  exec(command, {silent:true}, (code, stdout, stderr) => {
    logger.info(command);
    logger.debug(`stdout: ${stdout}`);
    logger.debug(`stderr: ${stderr}`);

    if (code !== 0) {
      return cb({command, code, stderr});
    }

    cb(null, stdout);
  });
}

export function mkdir(paths, cb) {
  const pathsBuilders = paths.map(path => function(asyncCallback) {
    shell(`mkdir -p ${path}`, err => {
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

export function setkeyv(keyv, progressKey, value, cb) {
  if (keyv && progressKey) {
    return keyv
      .set(progressKey, value)
      .then(() => cb(null));
  }
  cb(null);
}