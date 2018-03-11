import config from '../../config.json';
import async from 'async';
import {DepGraph} from 'dependency-graph';
import dockerfileGen from 'dockerfile-generator';
import fs from 'fs';
import { exec } from 'shelljs';
import {logger, hasAll, hasEither, last, head, tail, remove, splitTrimFilter, shell, mkdir, setkeyv} from '../../lib/util';

const APP_SPACE = config.appSpace;

export function parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, processId, cb) {
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

export function parseProcfs(pid, cb) {
  let cmdline, exe, bin, entrypointCmd, entrypointArgs, cwd;

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
    function(callback) {
      shell(`readlink -f /proc/${pid}/cwd`, (err, stdout) => {
        if (err) {
          return callback(err);
        }

        cwd = head(stdout, '\n');
        callback(null);
      });
    }
  ],
  function(err) {
    if (err) {
      return cb(err);
    }

    cb(null, {cmdline, exe, bin, entrypointCmd, entrypointArgs, cwd});
  });
}

export function parseDependencies(aptOutput) {
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

export function getPackagesSequence(exe, cb) {
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
        shell(`apt-rdepends ${corePackage} --state-follow=Installed --state-show=Installed -d`, (err, stdout) => {
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
          exec(`docker run -i --rm --entrypoint /bin/bash ${config.baseimage} -c "dpkg -L ${dep}"`, (code, stdout, stderr) => {
            if (code === 1) {
              packagesSequence.push(dep);
              return asyncCallback(null);
            }

            if ( !(code === 0 || code === 1)) {
              return asyncCallback({
                command: `docker run -i --rm --entrypoint /bin/bash ${config.baseimage} -c "dpkg -L ${dep}"`,
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

export function getOpennedFiles(pid, cb) {
  let procfs, opennedFiles;
  const stracePath = `${APP_SPACE}/strace`;

  async.series([
    function(callback) {
      parseProcfs(pid, (err, proc) => {
        logger.info('getOpennedFiles: parseProcfs');
        if (err) {
          return callback(err);
        }

        procfs = proc;
        callback(null);
      });
    },
    function(callback) {
      mkdir([stracePath], err => {
        logger.info('getOpennedFiles: mkdir');
        if (err) {
          return callback(err);
        }

        callback(null);
      });
    },
    function(callback) {
      // kill process
      async.someSeries([`service ${procfs.bin} stop`,`kill ${pid}`,`kill -9 ${pid}`], function(cmd, asyncCallback) {
        shell(cmd, err => {
          if (err) {
            if (err.code === 1) {
              return asyncCallback(null, false);
            } else {
              return asyncCallback(err);
            }
          }

          asyncCallback(null, true);
        });
      }, function(err, processStopped) {
        logger.info('getOpennedFiles: kill process');
        if (err) {
          return callback(err);
        }

        callback(processStopped ? null : 'Cannot stop process');
      });
    },
    function(callback) {
      // start strace
      const command = [
        `cd ${procfs.cwd} &&`,
        `strace -fe open ${procfs.entrypointCmd} ${(procfs.entrypointArgs).join(' ')}`,
        // `&> ${stracePath}/${procfs.bin}.log`].join(' '),
      ].join(' ');
      exec(command,
        (code, stdout, stderr) => {
          logger.info('getOpennedFiles: start strace');
          if (code !== 0) {
            return callback({command, code, stderr});
          }

          opennedFiles = stderr
            .split(`\n`)
            .map(line => line.split(`"`))
            .filter(line => line.length > 0 && line[0] === 'open(')
            .map(line => line[1]);
          callback(null);
        });
    },
    function(callback) {
      shell(`ps -C strace`, err => {
        logger.info('getOpennedFiles: check strace');
        if (err) {
          if (err.code === 1) {
            return callback(null);
          } else {
            return callback(err);
          }
        }

        // start strace killer
        const straceKiller = setInterval(() => {
          //kill if see any strace process in sleep state
          shell(`ps -C strace -o state= | grep S`, err => {
            logger.info('getOpennedFiles: check and kill strace');
            if (err && err.code === 1) {
              logger.debug('interval');
              return;
            }

            logger.debug('Killing strace');
            clearInterval(straceKiller);
            callback(err ? err : null);
          });
        }, 2000);
      });
    }
  ],
  function(err) {
    logger.info('getOpennedFiles: done');
    if (err) {
      return cb(err);
    }
    cb(null, {opennedFiles});
  });
}

export function getProcessMetadata(keyv, progressKey, pid, cb) {
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
      setkeyv(keyv, progressKey, 30, callback);
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

export function convert(keyv, progressKey, IGNORED_PORTS, IGNORED_PROGRAMS, pid, cb) {
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
      setkeyv(keyv, progressKey, 10, callback);
    },
    function(callback) {
      getProcessMetadata(null, null, pid, (err, meta) => {
        if (err) {
          return callback(err);
        }

        metadata = meta;
        callback(null);
      });
    },
    function(callback) {
      setkeyv(keyv, progressKey, 20, callback);
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
      setkeyv(keyv, progressKey, 30, callback);
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
      setkeyv(keyv, progressKey, 40, callback);
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
      setkeyv(keyv, progressKey, 50, callback);
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
      setkeyv(keyv, progressKey, 60, callback);
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
      setkeyv(keyv, progressKey, 70, callback);
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
      setkeyv(keyv, progressKey, 80, callback);
    },
    function(callback) {
      // issue: nginx: , causing docker tagging to fail
      shell(`cd ${buildPath} && docker build -t dd-agent/${program.replace(/\W/g, '')} .`, err => {
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

    cb(null);
  });
}