import http from 'http';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import bodyParser from 'body-parser';
import config from './config.json';
import {exec} from 'shelljs';
import async from 'async';
import {DepGraph} from 'dependency-graph';
import dockerfileGen from 'dockerfile-generator';
import fs from 'fs';

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

const APP_SPACE = '/tmp/dd-agent';
const IGNORED_PORTS = ['22','111', `${app.server.address().port}`];
const IGNORED_PROGRAMS = ['rpc.statd'];

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
      return cb({command, code, stderr});
    }

    cb(null, stdout);
  });
}

function parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, processId, cb) {
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
      .reduce(uniqueNetstatItems, [])
      .filter(i => (processId ? (i.pid === processId) : true));

    cb(null, {processes});
  });
}

app.get('/processes', (req, res) => {
  parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, null, (err, processes) => {
    if (err) {
      return res.status(404).json(err);
    }
    res.json(processes);
  });
});

// dependencies AND reverse dependencies

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
    }
  ],
  function(err) {
    if (err) {
      return cb(err);
    }

    cb(null, {cmdline, exe, bin, entrypointCmd, entrypointArgs});
  });
}

// shell(`type ${exe}`, (err, stdout) => {
//   if (err) {
//     return callback(err);
//   }

//   const lines = splitTrimFilter(stdout);

//   if(lines.length !== 1) {
//     return callback({
//       err: `Not one package from ${exe}`
//     });
//   }

//   corePackage = head(lines[0], ' is ');
//   callback(null);
// });

// function execInContainer(cmd, image, cb) {
//   //docker run -i --rm --entrypoint /bin/bash ubuntu:14.04 -c ""
//   shell(`docker run -i --rm --entrypoint /bin/bash ${image} -c "${cmd}"`, (err, stdout) => {
//     if(err) {
//       return cb(err);
//     }

//     cb(null, stdout);
//   });
// }

function remove(str, toRemove) {
  var final = str;
  while (final.indexOf(toRemove) > -1) {
    final = final.replace(toRemove,'');
  }
  return final;
}

function splitTrimFilter(str) {
  return str.split('\n').map(l => l.trim()).filter(l => l.length > 0);
}

function parseDependencies(aptOutput) {
  return aptOutput
    .split('\n')
    .filter(l => l.indexOf('->') > -1)
    .map(l => {
      const pair = l.split(' -> ');
      if (pair.length !== 2) {
        throw `Error parsing dependency pair ${pair}`;
      }
      const [pkgStr, depStr] = pair;
      const pkg = head(remove(pkgStr, `"`), '[');
      const dep = remove(head(remove(depStr, `"`), '['),';');
      return {pkg, dep};
    });
}

function getPackagesSequence(exe, cb) {
  const dependencyGraph = new DepGraph();
  let corePackages;
  var buildDeps = [];
  var reverseDeps = [];
  var reverseBuildDeps = [];
  const packagesSequence = [];

  async.series([
    function(callback) {
      shell(`dpkg -S ${exe}`, (err, stdout) => {
        if (err) {
          return callback(err);
        }

        corePackages = Array.from(
          /*eslint-disable */
          new Set(
          /*eslint-enable */
            stdout
              .split('\n')
              .filter(i => i.indexOf(':') > -1)
              .map(i => i.split(':')[0])
          )
        );
        callback(null);
      });
    },
    function(callback) {
      const buildDepsBuilders = corePackages.map(corePackage => function(asyncCallback) {
        shell(`apt-rdepends ${corePackage} --build-depends --state-follow=Installed --state-show=Installed -d`, (err, stdout) => {
          if (err) {
            return asyncCallback(err);
          }

          buildDeps = buildDeps.concat(parseDependencies(stdout));
          asyncCallback(null);
        });
      });

      async.series(buildDepsBuilders, function(err) {
        if (err) {
          return callback(err);
        }
        callback(null);
      });
    },
    function(callback) {
      const reverseDepsBuilders = corePackages.map(corePackage => function(asyncCallback) {
        shell(`apt-rdepends ${corePackage} -r --state-follow=Installed --state-show=Installed -d`, (err, stdout) => {
          if (err) {
            return asyncCallback(err);
          }

          reverseDeps = reverseDeps.concat(parseDependencies(stdout));
          asyncCallback(null);
        });
      });

      async.series(reverseDepsBuilders, function(err) {
        if (err) {
          return callback(err);
        }
        callback(null);
      });
    },
    function(callback) {
      const reverseBuildDepsBuilders = reverseDeps.
        map(pair => function(asyncCallback) {
          shell(`apt-rdepends ${pair.pkg} --build-depends --state-follow=Installed --state-show=Installed -d`, (err, stdout) => {
            if (err) {
              return asyncCallback(err);
            }
            reverseBuildDeps = reverseBuildDeps.concat(parseDependencies(stdout));
            asyncCallback(null);
          });
        });

      async.series(reverseBuildDepsBuilders, function(err) {
        if (err) {
          return callback(err);
        }

        callback(null);
      });
    },
    function(callback) {
      buildDeps
        .concat(reverseBuildDeps)
        .forEach(({pkg, dep}) => {
          dependencyGraph.addNode(pkg);
          dependencyGraph.addNode(dep);
          dependencyGraph.addDependency(pkg,dep);

          try {
            dependencyGraph.overallOrder();
          } catch (err) {
            if (err.toString().indexOf('Dependency Cycle Found') > -1) {
              dependencyGraph.removeDependency(pkg,dep);
            } else {
              throw (err);
            }
          }
        });

      callback(null);
    },
    function(callback) {
      const onlyNotInstalledInBaseImage = dependencyGraph
        .overallOrder()
        .map(dep => function(asyncCallback) {
          exec(`docker run -i --rm --entrypoint /bin/bash ubuntu:14.04 -c "dpkg -L ${dep}"`, (code, stdout, stderr) => {
            if (code === 1) {
              packagesSequence.push(dep);
              return asyncCallback(null);
            }

            if ( !(code === 0 || code === 1)) {
              return asyncCallback({
                command: `docker run -i --rm --entrypoint /bin/bash ubuntu:14.04 -c "dpkg -L ${dep}"`,
                stderr: stderr
              });
            }

            asyncCallback(null);
          });
        });

      async.series(onlyNotInstalledInBaseImage, function(err) {
        if (err) {
          return callback(err);
        }

        callback(null);
      });
    }
  ],
  function(err) {
    if (err) {
      return cb(err);
    }

    cb(null, packagesSequence);
  });
}

function getProcessMetadata(pid, cb) {
  let metadata;

  async.series([
    function(callback) {
      parseProcfs(pid, (err, meta) => {
        if (err) {
          return callback(err);
        }

        metadata = meta;
        callback(null);
      });
    },
    function(callback) {
      getPackagesSequence(metadata.exe, (err, packagesSequence) => {
        if (err) {
          return callback(err);
        }

        metadata.packagesSequence = packagesSequence;
        callback(null);
      });
    }
  ],
  function(err) {
    if (err) {
      return cb(err);
    }
    cb(null, metadata);
  });
}

function mkdir(paths, cb) {
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

function convert(pid, cb) {
  let port, program, metadata, buildPath, packagePath, workingDirectoryPath, debFiles, dockerfile;

  async.series([
    function(callback) {
      parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, pid, (err, {processes}) => {
        if (err) {
          return callback(err);
        }

        if (processes.length !== 1) {
          return callback(`Error finding process with pid ${pid}`);
        }

        port = processes[0].port;
        program = processes[0].program;
        buildPath = `${APP_SPACE}/${program}`;
        packagePath = `${buildPath}/packages`;
        workingDirectoryPath = `${buildPath}/workingDirectory`;
        callback(null);
      });
    },
    function(callback) {
      getProcessMetadata(pid, (err, meta) => {
        if (err) {
          return callback(err);
        }

        metadata = meta;
        callback(null);
      });
    },
    function(callback) {
      mkdir([buildPath, packagePath, workingDirectoryPath], err => {
        if (err) {
          return callback(err);
        }

        callback(null);
      });
    },
    function(callback) {
      const runScriptContent = `#!/bin/bash\\n${metadata.entrypointCmd} ${metadata.entrypointArgs.join(' ')} && while ps -C ${metadata.entrypointCmd}; do echo -n stopping process from going background ... && sleep 3; done`;

      shell(`echo '${runScriptContent}' > ${workingDirectoryPath}/cmdScript.sh`, err => {
        if (err) {
          return callback(err);
        }

        callback(null);
      });
    },
    function(callback) {
      const repackers = metadata
        .packagesSequence
        .map(p => function(asyncCallback) {
          shell(`cd ${packagePath} && dpkg-repack ${p}`, err => {
            if (err) {
              return asyncCallback(err);
            }

            asyncCallback(null);
          });
        });

      async.series(repackers, err => {
        if (err) {
          return callback(err);
        }

        callback(null);
      });
    },
    function(callback) {
      shell(`cd ${packagePath} && ls | grep .deb`, (err, stdout) => {
        if (err) {
          if (err.code && err.code === 1) {
            return callback(null);
          }
          return callback(err);
        }

        debFiles = splitTrimFilter(stdout);
        callback(null);
      });
    },
    function(callback) {
      const copyInstructions = [
        {
          'src': 'workingDirectory',
          'dst': '/workingDirectory'
        },
        {
          'src': 'packages',
          'dst': '/packages'
        },
        {
          'src': 'workingDirectory/cmdScript.sh',
          'dst': '/workingDirectory'
        }
      ];

      const runInstructions = [{
        'command': 'chmod',
        'args': ['+x', '/workingDirectory/cmdScript.sh']
      }]
        .concat(debFiles
          .map(p => ({
            'command': 'dpkg',
            'args': ['-i','--force-depends',`/packages/${p}`,] //dependency graph took care of dependencies
          })));

      const dockerfileContent = {
        'imagename': 'ubuntu',
        'imageversion': '14.04',
        'copy': copyInstructions,
        'run': runInstructions,
        'workdir': 'workingDirectory',
        'expose': [port],
        'cmd': {
          'command': './cmdScript.sh'
        }
      };

      dockerfileGen.generate(JSON.stringify(dockerfileContent), (err,result) => {
        if (err) {
          return callback(err);
        }

        dockerfile = result;
        callback(null);
      });
    },
    function(callback) {
      fs.writeFile(`${buildPath}/Dockerfile`, dockerfile, err => {
        if (err) {
          return callback(err);
        }

        callback(null);
      });
    },
    function(callback) {
      shell(`cd ${buildPath} && docker build -t ${program} .`, err => {
        if (err) {
          return callback(err);
        }

        callback(null);
      });
    }
  ],
  function(err) {
    if (err) {
      return cb(err);
    }

    cb(null, dockerfile);
  });
}

app.get('/processMetadata/:pid', (req, res) => {
  getProcessMetadata(req.params.pid, (err, metadata) => {
    if (err) {
      return res.status(404).json(err);
    }
    res.json(metadata);
  });
});

app.get('/convert/:pid', (req, res) => {
  convert(req.params.pid, (err, dockerfile) => {
    if (err) {
      return res.status(404).json(err);
    }
    res.json(dockerfile);
  });
});

app.get('/docs', (req, res) => {
  res.send('Hello world!');
});

export default app;