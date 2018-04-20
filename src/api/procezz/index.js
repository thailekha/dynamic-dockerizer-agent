import config from '../../config.json';
import async from 'async';
import {DepGraph} from 'dependency-graph';
import fs from 'fs';
import { exec } from 'shelljs';
import {logger, hasAll, hasEither, last, head, tail, init, remove, shell, mkdir, injectSetkeyv} from '../../lib/util';
import {listImages} from '../../lib/image';
import _ from 'lodash';

const APP_SPACE = config.appSpace;
const CHECK_STDERR_FOR_ERROR = true; //some commmands output warning message to stderr
const IGNORED_PATHS = ['/mnt','/sys','/proc','/dev','/run','/tmp/dd-agent'];
const ACCEPTED_PATHS_FOR_SHORTENING = ['root', 'home', 'opt', 'usr', 'var'];

function pidCommand(command, escapeDollarSign = true) {
  return `${escapeDollarSign ? '\\$' : '$'}(pidof ${command} | sed 's/\\([0-9]*\\)/-p \\1/g')`;
}

export function parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, processId, cb) {
  exec('netstat --tcp --listening --numeric --program | awk \'{print $4,$7}\'', {silent:true}, (code, stdout, stderr) => {
    if (code !== 0 || stderr) {
      return cb({
        message: 'Failed to gather processes listening on network'
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
      .map(i => (i.indexOf('::') > -1 ? i.replace('::', '0.0.0.0') : i) )
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
      shell(`cat /proc/${pid}/cmdline`, CHECK_STDERR_FOR_ERROR, (err, stdout) => {
        if (err) {
          return callback({
            message: 'Failed to find the cmd'
          });
        }

        cmdline = stdout;
        callback(null);
      });
    },
    function(callback) {
      shell(`readlink -f /proc/${pid}/exe`, CHECK_STDERR_FOR_ERROR, (err, stdout) => {
        if (err) {
          return callback({
            message: 'Failed to find the executable file'
          });
        }

        exe = head(stdout,'\n');
        bin = head(last(exe,'/'),'\n'); //strip new line here !!!
        callback(null);
      });
    },
    function(callback) {
      exec(`which ${bin}`, {silent:true}, (code, _, stderr) => {
        if (code !== 0 || stderr) {
          entrypointCmd = head(exe,'\n');
        } else {
          entrypointCmd = bin;
        }

        const unresolvedEntrypointArgs = tail(cmdline,'\0').map(a => a.trim()).filter(a => a.length > 0);

        entrypointArgs = [];

        const entrypointArgsFilesResolver = unresolvedEntrypointArgs.map(f => function(asyncCallback) {
          fs.realpath(f, (err, resolvedFile) => {
            if (!err) {
              entrypointArgs.push(resolvedFile);
            } else {
              entrypointArgs.push(f);
            }
            asyncCallback(null);
          });
        });

        //must use series here to preserve args order
        async.series(entrypointArgsFilesResolver, () => {
          callback(null);
        });
      });
    },
    function(callback) {
      shell(`readlink -f /proc/${pid}/cwd`, CHECK_STDERR_FOR_ERROR, (err, stdout) => {
        if (err) {
          return callback({
            message: 'Failed to find the current working directory'
          });
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
  var packagesSequence = [];

  async.series([
    function(callback) {
      shell(`dpkg -S ${exe}`, CHECK_STDERR_FOR_ERROR, (err, stdout) => {
        if (err) {
          logger.debug('Failed to search for packages from the executable file, so will only copy the executable file instead');
          corePackages = [];
          return callback(null);
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
        shell(`apt-rdepends ${corePackage} --state-follow=Installed --state-show=Installed -d`, !CHECK_STDERR_FOR_ERROR, (err, stdout) => {
          if (err) {
            return asyncCallback(err);
          }

          buildDeps = buildDeps.concat(parseDependencies(stdout));
          asyncCallback(null);
        });
      });

      async.series(buildDepsBuilders, function(err) {
        if (err) {
          return callback({
            message: 'Failed to get dependencies of core packages'
          });
        }
        callback(null);
      });
    },
    function(callback) {
      const reverseDepsBuilders = corePackages.map(corePackage => function(asyncCallback) {
        shell(`apt-rdepends ${corePackage} -r --state-follow=Installed --state-show=Installed -d`, !CHECK_STDERR_FOR_ERROR, (err, stdout) => {
          if (err) {
            return asyncCallback(err);
          }

          reverseDeps = reverseDeps.concat(parseDependencies(stdout));
          asyncCallback(null);
        });
      });

      async.series(reverseDepsBuilders, function(err) {
        if (err) {
          return callback({
            message: 'Failed to get reverse dependencies of core packages'
          });
        }
        callback(null);
      });
    },
    function(callback) {
      const reverseBuildDepsBuilders = reverseDeps.
        map(pair => function(asyncCallback) {
          shell(`apt-rdepends ${pair.pkg} --build-depends --state-follow=Installed --state-show=Installed -d`, !CHECK_STDERR_FOR_ERROR, (err, stdout) => {
            if (err) {
              return asyncCallback(err);
            }
            reverseBuildDeps = reverseBuildDeps.concat(parseDependencies(stdout));
            asyncCallback(null);
          });
        });

      async.series(reverseBuildDepsBuilders, function(err) {
        if (err) {
          return callback({
            message: 'Failed to get build dependencies of the reverse dependencies of core packages'
          });
        }

        callback(null);
      });
    },
    function(callback) {
      try {
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
      } catch (err) {
        //cannot break the loop in foreach so catch the err here
        const errMsg = 'Failed to build package dependency graph';
        err.message = err.message ? (err.message += `\n${errMsg}`) : errMsg;
        return callback(err);
      }

      callback(null);
    },
    function(callback) {
      const filterDepsCommand = `docker run -i --rm --entrypoint /bin/bash ${config.baseimage} -c "for PACKAGE in ${dependencyGraph.overallOrder().join(' ')}; do if ! dpkg -L \\$PACKAGE &>/dev/null; then echo \\$PACKAGE; fi; done"`;
      logger.debug(`Filtering dependencies that are already installed in baseimage with command: ${filterDepsCommand}`);
      exec(filterDepsCommand, {silent:true}, (code, stdout) => {
        if (code !== 0) {
          return callback({
            message: 'Failed to filter the package dependency graph'
          });
        }

        stdout
          .split('\n')
          .map(line => line.trim())
          .filter(line => line.length > 0)
          .forEach(dep => packagesSequence.push(dep));

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

function prepareWholeVMContainer(cb) {
  let images;
  async.series([
    function(callback) {
      listImages((err, data) => {
        if (err) {
          return callback(err);
        }

        images = data;
        callback(null);
      });
    },
    function(callback) {
      if (images.filter(image => image.RepoTags.indexOf(`${config.vmimage}:latest`) > -1).length === 0) {
        return shell(`cd / && tar -c --exclude=mnt --exclude=sys --exclude=proc --exclude=dev --exclude=var/lib/docker . | docker import - ${config.vmimage}`, !CHECK_STDERR_FOR_ERROR, err => {
          if (err) {
            return callback({
              message: 'Failed to prepare whole VM container'
            });
          }

          callback(null);
        });
      }
      callback(null);
    }
  ],
  function(err) {
    if (err) {
      return cb(err);
    }
    cb(null);
  });
}

function shortenPaths(paths) {
  var shortenedPaths = [];

  paths.forEach((thisPath, _, array) => {
    const thisPathParts = tail(thisPath, '/'); //first is '' so skip it

    if (ACCEPTED_PATHS_FOR_SHORTENING.indexOf(thisPathParts[0]) < 0) {
      return shortenedPaths.push(thisPath);
    }

    var diffIndex = null;

    array.forEach(thatPath => {
      if (thatPath === thisPath) {
        return;
      }

      const thatPathParts = tail(thatPath,'/');
      thisPathParts.forEach((part, index) => {
        if (thatPathParts.length <= index) {
          return;
        }

        if (part === thatPathParts[index] && (diffIndex === null || index > diffIndex)) {
          diffIndex = index;
        }
      });
    });

    diffIndex += 1;

    if (diffIndex > 3) {
      shortenedPaths.push(thisPath.split('/').slice(0,diffIndex).join('/'));
    } else {
      shortenedPaths.push(thisPath);
    }
  });

  return _.uniq(shortenedPaths);
}

function getOpennedFiles(pid, cb) {
  let procfs, reducedOpennedFiles;
  const relativePaths = [];
  const symlinks = [];
  const opennedFiles = [];
  const opennedRegularFiles = [];
  const opennedDirectories = [];
  var traceOutput = "";

  async.series([
    function(callback) {
      prepareWholeVMContainer(err => {
        if (err) {
          return callback(err);
        }

        callback(null);
      });
    },
    function(callback) {
      parseProcfs(pid, (err, proc) => {
        if (err) {
          return callback(err);
        }

        procfs = proc;
        callback(null);
      });
    },
    function(callback) {
      fs.readdir(`/proc/${pid}/fd`, function(err, items) {
        if (err) {
          return callback({
            message: 'Failed to read files currently openned by the process'
          });
        }

        const currentlyOpennedFilesResolver = items.map(i => asyncCallback => {
          fs.realpath(`/proc/${pid}/fd/${i}`, (err, resolvedFile) => {
            if (err) {
              return asyncCallback(null);
            }

            fs.lstat(resolvedFile, (err, resolvedFileStats) => {
              if (err) {
                return asyncCallback(null);
              }

              if (resolvedFileStats.isDirectory() || resolvedFileStats.isFile()) {
                opennedFiles.push(resolvedFile);
              }

              asyncCallback(null);
            });
          });
        });

        async.parallel(currentlyOpennedFilesResolver, err => {
          if (err) {
            return callback({
              message: 'Failed to read files currently openned by the process'
            });
          }
          callback(null);
        });
      });
    },
    function(callback) {
      shell(`kill ${pid}`, CHECK_STDERR_FOR_ERROR, err => {
        if (err) {
          return callback({
            message: 'Failed to kill the process'
          });
        }
        callback(null);
      });
    },
    function(callback) {
      //container created by dockerode  cannot be connected to host network
      //would give `server error - container cannot be disconnected from host network or connected to host network`
      const straceCommand = [
        `cd ${procfs.cwd} &&`,
        `strace -fe trace=file ${procfs.entrypointCmd} ${(procfs.entrypointArgs).join(' ')} &&`,
        `echo strace attach ${pidCommand(procfs.entrypointCmd)} &&`,
        `strace -fe trace=file ${pidCommand(procfs.entrypointCmd)}`
      ].join(' ');

      const straceContainerCommand = `docker run --name strace-${pid} --network=host -i --rm --privileged --entrypoint /bin/bash ${config.vmimage} -c "${straceCommand}"`;

      logger.info(`Starting container to trace openned files with command, to test it: ${straceContainerCommand}`);

      exec(straceContainerCommand, {silent:true, async:true}).stderr.on('data', data => {
        traceOutput += data;
      });

      callback(null);
    },
    function(callback) {
      setTimeout(() => {
        logger.info(`Preparing to kill strace container`);
        var lock = false;
        const straceKiller = setInterval(() => {

          if (lock) {
            logger.debug('Strace killer is blocked');
            return;
          }

          lock = true;

          const removeContainer = cb => {
            shell(`docker rm -f strace-${pid}`, CHECK_STDERR_FOR_ERROR, err => {
              if (err) {
                return cb({
                  message: 'Failed to stop tracing for openned files'
                });
              }

              cb(null);
            });
          };

          shell(`docker ps | grep strace-${pid}`, CHECK_STDERR_FOR_ERROR, err => {
            if (err && err.code === 1) {
              // container not running
              clearInterval(straceKiller);
              return removeContainer(callback);
            }

            //remove strace container if the strace process in it enters the sleep state
            shell(`docker exec strace-${pid} /bin/bash -c "ps -C strace -o state= | grep S"`, CHECK_STDERR_FOR_ERROR, err => {
              if (err && err.code === 1) {
                logger.debug('strace interval');
                lock = false;
                return;
              }

              clearInterval(straceKiller);

              if (err) {
                return callback({
                  message: 'Failed to stop tracing for openned files'
                });
              }

              removeContainer(callback);
            });
          });
        }, 1000);
      }, 1000 * 60 * config.straceTimeoutInMinutes);
    },
    function(callback) {
      const straceParser = (syscalls, match = true) =>
        traceOutput
          .split(`\n`)
          .filter(line => line.indexOf('("') > -1 && line.indexOf('= -1') < 0)
          .map(line => line.split(`"`))
          .filter(lineParts => lineParts.length > 1 && (match ? syscalls.filter(sc => lineParts[0].indexOf(sc) > -1).length > 0 : syscalls.filter(sc => lineParts[0].indexOf(sc) > -1).length === 0))
          .map(line => line[1])
          .filter(path => IGNORED_PATHS.filter(ignored => path.indexOf(ignored) === 0).length === 0)
          .filter(path => '/tmp' !== path); //edge case

      const opennedFilesResolver =
        straceParser(['open(', 'openat('])
          .filter(file => {
            // strace may not pick up absolute path
            if (file.length > 0 && file[0] === '/') {
              return true;
            }
            relativePaths.push(file);
            return false;
          })
          .map(f => function(asyncCallback) {
            fs.lstat(f, (err, stats) => {
              if (err) {
                if (err.code === 'ENOENT') {
                  return asyncCallback(null); //sometimes a process create then delete a temporary file
                }
                return asyncCallback(err);
              }

              if (stats.isSymbolicLink()) {
                symlinks.push(f);
              }

              fs.realpath(f, (err, resolvedFile) => {
                if (err) {
                  return asyncCallback(null);
                }

                if (f !== resolvedFile) {
                  let temp;

                  if (init(f, '/')) {
                    temp = init(f, '/').join('/');
                  }

                  while (temp) {
                    if (fs.lstatSync(temp).isSymbolicLink()) {
                      symlinks.push(temp);
                    }

                    temp = init(temp, '/');
                    if (temp) {
                      temp = temp.join('/');
                    }
                  }
                }

                opennedFiles.push(resolvedFile);
                asyncCallback(null);
              });
            });
          });

      async.parallel(opennedFilesResolver, err => {
        if (err) {
          const errMsg = 'Failed to collect files that process openned';
          err.message = err.message ? (err.message += `\n${errMsg}`) : errMsg;
          return callback(err);
        }

        callback(null);
      });
    },
    function(callback) {
      var shortenedPaths = shortenPaths(opennedFiles);
      var tempShortenedPaths = shortenPaths(shortenedPaths);

      while (tempShortenedPaths.length < shortenedPaths.length) {
        shortenedPaths = tempShortenedPaths;
        tempShortenedPaths = shortenPaths(tempShortenedPaths);
      }

      reducedOpennedFiles = shortenedPaths;
      callback(null);
    },
    function(callback) {
      const realpathResolver = reducedOpennedFiles.map(f => asyncCallback => {
        fs.lstat(f, (err, stats) => {
          if (err) {
            return asyncCallback(err);
          }

          if (stats.isDirectory()) {
            opennedDirectories.push(f);
          } else if (stats.isFile()) {
            opennedRegularFiles.push(f);
          } else {
            return asyncCallback({
              message: 'Path is neither a file nor a directory'
            });
          }

          asyncCallback(null);
        });
      });

      async.series(realpathResolver, err => {
        if (err) {
          return callback({
            message: 'Failed to collect parent symlinks'
          });
        }

        callback(null);
      });
    },
    function(callback) {
      logger.debug(`Warning: relative paths: ${relativePaths.join('\n')}`);
      logger.debug(`Detected openned files: ${opennedFiles.join('\n')}`);
      logger.debug(`Detected symlinks: ${symlinks.join('\n')}`);
      logger.debug(`Detected openned regular files: ${opennedRegularFiles.join('\n')}`);
      logger.debug(`Detected openned directories: ${opennedDirectories.join('\n')}`);

      callback(null);
    }
  ],
  function(err) {
    if (err) {
      return cb(err);
    }
    cb(null, {
      symlinks: _.uniq(symlinks),
      opennedRegularFiles: _.uniq(opennedRegularFiles),
      opennedDirectories: _.uniq(opennedDirectories),
      restartCmd: `cd ${procfs.cwd} && ${procfs.entrypointCmd} ${(procfs.entrypointArgs).join(' ')} &`
    });
  });
}

export function inspectProcess(keyv, progressKey, pid, cb) {
  let metadata;

  async.series(injectSetkeyv(keyv, progressKey,[
    function(callback) {
      getProcessMetadata(pid, (err, meta) => {
        if (err) {
          return callback(err);
        }

        metadata = meta;
        callback(null);
      });
    }
  ]),
  function(err) {
    if (err) {
      return cb(err);
    }

    cb(null, metadata);
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

export function convert(keyv, progressKey, IGNORED_PORTS, IGNORED_PROGRAMS, pid, cb) {
  let port
    , program
    , metadata
    , buildPath
    , workingDirectoryPath
    , aptPath
    , extraFilesPath
    , symlinks
    , opennedRegularFiles
    , opennedDirectories
    , restartCmd;

  async.series(injectSetkeyv(keyv, progressKey,[
    function(callback) {
      parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, pid, (err, {processes}) => {
        if (err) {
          return callback(err);
        }

        if (processes.length !== 1) {
          return callback({
            message: `Failed to find process with pid ${pid}`
          });
        }

        port = processes[0].port;
        program = processes[0].program;
        buildPath = `${APP_SPACE}/${program}${port}`;
        workingDirectoryPath = `${buildPath}/workingDirectory`;
        aptPath = `${buildPath}/apt`;
        extraFilesPath = `${buildPath}/extraFiles`;
        callback(null);
      });
    },
    function(callback) {
      mkdir([buildPath, workingDirectoryPath, aptPath, extraFilesPath], err => {
        if (err) {
          return callback({
            message: 'Failed to update folder for building Docker image for the process'
          });
        }

        callback(null);
      });
    },
    function(callback) {
      shell(`cp -rf /var/lib/apt ${aptPath}/varlib`, !CHECK_STDERR_FOR_ERROR, err => {
        if (err) {
          return callback({
            message: 'Failed to preserve apt'
          });
        }

        callback(null);
      });
    },
    function(callback) {
      shell(`cp -rf /etc/apt ${aptPath}/etc`, !CHECK_STDERR_FOR_ERROR, err => {
        if (err) {
          return callback({
            message: 'Failed to preserve apt'
          });
        }

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
      const mainCommand = `${metadata.packagesSequence.length === 0 ? metadata.exe : metadata.entrypointCmd}`;
      const straceCommand = `strace -o /dev/null -fe trace=process ${mainCommand} ${metadata.entrypointArgs.join(' ')} && echo strace attach ${pidCommand(mainCommand, false)} && strace -o /dev/null -fe trace=process ${pidCommand(mainCommand, false)}`;
      const runScriptContent = `#!/bin/bash\n${straceCommand}`;

      logger.debug(`Runscript: ${runScriptContent}`);

      fs.writeFile(`${workingDirectoryPath}/cmdScript.sh`, runScriptContent, err => {
        if (err) {
          return callback({
            message: 'Failed to generate run script'
          });
        }

        callback(null);
      });
    },
    function(callback) {
      getOpennedFiles(pid, (err, opennedFiles) => {
        if (err || !opennedFiles || !opennedFiles.symlinks || !opennedFiles.opennedRegularFiles || !opennedFiles.opennedDirectories) {
          const errMsg = 'Failed to collect files that process openned';
          if (err) {
            err.message = err.message ? (err.message += `\n${errMsg}`) : errMsg;
            return callback(err);
          }
          return callback({
            message: errMsg
          });
        }

        symlinks = opennedFiles.symlinks;
        opennedRegularFiles = opennedFiles.opennedRegularFiles;
        opennedDirectories = opennedFiles.opennedDirectories;
        restartCmd = opennedFiles.restartCmd;
        callback(null);
      });
    },
    function(callback) {
      if (metadata.packagesSequence.length === 0) {
        opennedRegularFiles.push(metadata.exe);
      }

      async.parallel(
        metadata.entrypointArgs.map(a =>
          asyncCallback => {
            fs.lstat(a, (err, stats) => {
              if (!err) {
                if (stats.isDirectory()) {
                  opennedDirectories.push(a);
                } else if (stats.isFile()) {
                  opennedRegularFiles.push(a);
                }
              }
              asyncCallback(null);
            });
          }
        ),
        () => {
          callback(null);
        }
      );
    },
    function(callback) {
      const syncOpennedDirectories = opennedDirectories.map(path => asyncCallback =>
        shell(`rsync -avRW /.${path}/ ${extraFilesPath}`, CHECK_STDERR_FOR_ERROR, err => {
          if (err) {
            return asyncCallback(err);
          }

          asyncCallback(null);
        })
      );

      const syncSymlinks = symlinks.map(path => asyncCallback =>
        shell(`rsync -avRW /.${path} ${extraFilesPath}`, CHECK_STDERR_FOR_ERROR, err => {
          if (err) {
            return asyncCallback(err);
          }

          asyncCallback(null);
        })
      );

      const syncOpennedRegularFile = opennedRegularFiles.map(path => asyncCallback =>
        shell(`rsync -avRW /.${path} ${extraFilesPath}`, CHECK_STDERR_FOR_ERROR, err => {
          if (err) {
            return asyncCallback(err);
          }

          asyncCallback(null);
        })
      );

      async.series(syncOpennedDirectories.concat(syncOpennedRegularFile).concat(syncSymlinks), err => {
        if (err) {
          return callback({
            message: 'Failed to import files that process openned'
          });
        }

        callback(null);
      });
    },
    function(callback) {
      logger.info('Restarting the process');
      exec(restartCmd, {silent:true, async:true});
      callback(null);
    },
    function(callback) {
      const multipleCommandsDelimiter = `; \\\n  `;

      const dockerfileContent = [
        `FROM ${config.baseimage}`,
        `COPY apt /apt`,
        `RUN rm -rf /var/lib/apt/* || echo Failed to overwrite apt settings; \\`,
        `  rm -rf /etc/apt/* || echo Failed to overwrite apt settings; \\`,
        `  cp -rf /apt/varlib/. /var/lib/apt/. || echo Failed to overwrite apt settings; \\`,
        `  cp -rf /apt/etc/. /etc/apt/. || echo Failed to overwrite apt settings;`,
        `RUN apt-get update || echo 'apt-get update failed, installing anyway'`,
        `RUN apt-get install --no-install-recommends --no-install-suggests -f -y --force-yes rsync strace ${metadata.packagesSequence.join(' ')}`,
        `COPY extraFiles /extraFiles`,
        opennedDirectories.length > 0 ? `RUN ${opennedDirectories.map(path => `rsync -avRW /extraFiles/.${path}/ / `).join(multipleCommandsDelimiter)}` : '',
        opennedRegularFiles.length > 0 ? `RUN ${opennedRegularFiles.map(path => `rsync -avRW /extraFiles/.${path} / `).join(multipleCommandsDelimiter)}` : '',
        symlinks.length > 0 ? `RUN ${symlinks.map(path => `rsync -avRW /extraFiles/.${path} / || echo Failed to import symlink`).join(multipleCommandsDelimiter)}` : '',

        //Clean up and reduce image size
        `RUN rm -rf /var/lib/apt/lists/*; \\`,
        `  rm -rf /var/cache/apt/*; \\`,
        `  rm -rf /apt; \\`,
        `  rm -rf /extraFiles;`,
        `COPY workingDirectory /workingDirectory`,
        `RUN chmod +x /workingDirectory/cmdScript.sh`,
        `WORKDIR workingDirectory`,
        `EXPOSE ${port}`,
        `CMD ["./cmdScript.sh"]`,
      ].join('\n');

      logger.debug(dockerfileContent);

      fs.writeFile(`${buildPath}/Dockerfile`, dockerfileContent, err => {
        if (err) {
          return callback({
            message: 'Failed to serialize Dockerfile'
          });
        }

        callback(null);
      });
    },
    function(callback) {
      shell(`cd ${buildPath} && docker build -t dd-agent/${program.replace(/\W/g, '')}${port} .`, CHECK_STDERR_FOR_ERROR, err => {
        if (err) {
          return callback({
            message: 'Failed to build Docker image'
          });
        }

        callback(null);
      });
    },
    function(callback) {
      shell(`rm -rf ${buildPath}`, CHECK_STDERR_FOR_ERROR, err => {
        if (err) {
          return callback({
            message: 'Failed to delete build path'
          });
        }

        callback(null);
      });
    }
  ]),
  function(err) {
    if (err) {
      return cb(err);
    }

    cb(null);
  });
}
