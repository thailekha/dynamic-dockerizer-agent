import config from '../../config.json';
import async from 'async';
import {DepGraph} from 'dependency-graph';
import fs from 'fs';
import { exec } from 'shelljs';
import {logger, hasAll, hasEither, last, head, tail, init, remove, splitTrimFilter, shell, mkdir, injectSetkeyv} from '../../lib/util';
import {listImages} from '../../lib/image';
import Docker from 'dockerode';
import _ from 'lodash';

const APP_SPACE = config.appSpace;
const CHECK_STDERR_FOR_ERROR = true; //some commmands output warning message to stderr

const docker = new Docker({
  socketPath: '/var/run/docker.sock'
});

export function parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, processId, cb) {
  exec('netstat --tcp --listening --numeric --program | awk \'{print $4,$7}\'', (code, stdout, stderr) => {
    // if terraform command time out, no response is returned by express, why?
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
      exec(`which ${bin}`, (code, _, stderr) => {
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
  const packagesSequence = [];

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
      const onlyNotInstalledInBaseImage = dependencyGraph
        .overallOrder()
        .map(dep => function(asyncCallback) {
          exec(`docker run -i --rm --entrypoint /bin/bash ${config.baseimage} -c "dpkg -L ${dep}"`, (code, stdout, stderr) => {
            if (code === 1) {
              packagesSequence.push(dep);
              return asyncCallback(null);
            }

            if ( !(code === 0 || code === 1) || stderr ) {
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
          return callback({
            message: 'Failed to filter the package dependency graph'
          });
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

    if (['root', 'home', 'opt'].indexOf(thisPathParts[0]) < 0) {
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
  let procfs, opennedFiles;
  var opennedFilesChunks = [];
  var symlinksOpennedFiles = [];
  var resolvedOpennedFiles = []; //cater for symlinks
  var shortenedOpennedFiles = [];

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
      const command = [
        `cd ${procfs.cwd} &&`,
        `strace -fe open,openat ${procfs.entrypointCmd} ${(procfs.entrypointArgs).join(' ')}`,
      ].join(' ');

      const STRACE_CONTAINER = {
        Image: config.vmimage,
        AttachStdin: false,
        AttachStdout: true,
        AttachStderr: true,
        Tty: true,
        Cmd: ['/bin/bash', '-c', command],
        OpenStdin: false,
        StdinOnce: false
      };

      docker.createContainer(STRACE_CONTAINER, function(err, container) {
        if (err) {
          const errMsg = 'Failed to create strace container';
          err.message = err.message ? (err.message += `\n${errMsg}`) : errMsg;
          return callback(err);
        }

        container.start((err, data) => {
          if (err || data === null) {
            const errMsg = 'Failed to start strace container';
            err.message = err.message ? (err.message += `\n${errMsg}`) : errMsg;
            return callback(err);
          }

          logger.info(`Started container to trace openned files with command, to test it: docker run -i --rm --entrypoint /bin/bash vmimage -c "${command}"`);

          container.attach({
            stream: true,
            stdout: true,
            stderr: true,
            tty: true
          }, (err, stream) => {
            if (err) {
              const errMsg = 'Failed to attach to strace container';
              err.message = err.message ? (err.message += `\n${errMsg}`) : errMsg;
              return callback(err);
            }

            stream.on('data', chunk => opennedFilesChunks.push(chunk));

            setTimeout(() => {
              const straceKiller = setInterval(() => {
                //remove strace container if the strace process in it enters the sleep state
                shell(`docker exec ${container.id} /bin/bash -c "ps -C strace -o state= | grep S"`, CHECK_STDERR_FOR_ERROR, err => {
                  if (err && err.code === 1) {
                    logger.debug('strace interval');
                    return;
                  }

                  clearInterval(straceKiller);

                  if (err) {
                    return callback({
                      message: 'Failed to stop tracing for openned files'
                    });
                  }

                  shell(`docker rm -f ${container.id}`, CHECK_STDERR_FOR_ERROR, err => {
                    if (err) {
                      return callback({
                        message: 'Failed to stop tracing for openned files'
                      });
                    }

                    callback(null);
                  });
                });
              }, 3000);
            }, 5000);
          });
        });
      });
    },
    function(callback) {
      opennedFiles = Buffer
        .concat(opennedFilesChunks)
        .toString()
        .split(`\n`)
        .filter(line => line.indexOf('= -1') < 0)
        .map(line => line.split(`"`))
        .filter(lineParts => lineParts.length > 1 && (lineParts[0].indexOf('open(') > -1 || lineParts[0].indexOf('openat(') > -1))
        .map(line => line[1])
        .filter(path => ['/mnt','/sys','/proc','/dev','/run'].filter(ignored => path.indexOf(ignored) === 0).length === 0);

      // strace picks up full dir already
      const opennedFilesResolver = opennedFiles.map(f => function(asyncCallback) {
        fs.lstat(f, (err, stats) => {
          if (err) {
            if (err.code === 'ENOENT') {
              return asyncCallback(null); //sometimes a process create then delete a temporary file
            }
            return asyncCallback(err);
          }

          fs.realpath(f, (err, resolvedFile) => {
            if (err) {
              if (err.code === 'ENOENT') {
                return asyncCallback(null); //broken symlink
              }
              return asyncCallback(err);
            }

            resolvedOpennedFiles.push(resolvedFile);

            if (stats.isSymbolicLink()) {
              symlinksOpennedFiles.push({
                linkPath: f,
                realPath: resolvedFile,
                pathToCreate: init(f, '/').join('/')
              });
              return asyncCallback(null);
            }

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
      var shortenedPaths = shortenPaths(resolvedOpennedFiles);
      var tempShortenedPaths = shortenPaths(shortenedPaths);

      while (tempShortenedPaths.length < shortenedPaths.length) {
        shortenedPaths = tempShortenedPaths;
        tempShortenedPaths = shortenPaths(tempShortenedPaths);
      }

      shortenedOpennedFiles = shortenedPaths;
      callback(null);
    },
    function(callback) {
      logger.debug(`Raw openned files: ${opennedFiles.join('\n')}`);
      logger.debug(`Resolved openned files: ${resolvedOpennedFiles.join('\n')}`);
      logger.debug(`Symlinks to create: ${symlinksOpennedFiles.map(i => i.toString()).join('\n')}`);

      callback(null);
    }
  ],
  function(err) {
    if (err) {
      return cb(err);
    }
    cb(null, {opennedFiles: shortenedOpennedFiles, symlinks: symlinksOpennedFiles});
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
    },
    function(callback) {
      getOpennedFiles(pid, (err, opennedFiles) => {
        if (err || !opennedFiles || !opennedFiles.opennedFiles) {
          const errMsg = 'Failed to collect files that process openned';
          if (err) {
            err.message = err.message ? (err.message += `\n${errMsg}`) : errMsg;
            return callback(err);
          }
          return callback({
            message: errMsg
          });
        }

        metadata.opennedFiles = opennedFiles.opennedFiles;
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
  let port, program, metadata, buildPath, packagePath, workingDirectoryPath, aptPath, extraFilesPath, extraFiles, symlinksToCreate, debFiles;

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
        buildPath = `${APP_SPACE}/${program}`;
        packagePath = `${buildPath}/packages`;
        workingDirectoryPath = `${buildPath}/workingDirectory`;
        aptPath = `${buildPath}/apt`;
        extraFilesPath = `${buildPath}/extraFiles`;
        callback(null);
      });
    },
    function(callback) {
      mkdir([buildPath, packagePath, workingDirectoryPath, aptPath, extraFilesPath], err => {
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
      shell(`cd ${packagePath} && dpkg-repack apt strace`, !CHECK_STDERR_FOR_ERROR, err => {
        if (err) {
          return callback({
            message: 'Failed to repack apt and strace'
          });
        }

        callback(null);
      });
    },
    function(callback) {
      shell(`cd ${packagePath} && ls | grep .deb`, CHECK_STDERR_FOR_ERROR, (err, stdout) => {
        if (err) {
          if (err.code && err.code === 1) {
            return callback(null);
          }
          return callback({
            message: 'Failed to gather repacked dependencies .deb files'
          });
        }

        debFiles = splitTrimFilter(stdout);
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
      const runScriptContent = `#!/bin/bash\\n strace -fe trace=process ${metadata.packagesSequence.length === 0 ? metadata.exe : metadata.entrypointCmd} ${metadata.entrypointArgs.join(' ')}`;

      shell(`echo '${runScriptContent}' > ${workingDirectoryPath}/cmdScript.sh`, CHECK_STDERR_FOR_ERROR, err => {
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
        if (err || !opennedFiles || !opennedFiles.opennedFiles) {
          const errMsg = 'Failed to collect files that process openned';
          if (err) {
            err.message = err.message ? (err.message += `\n${errMsg}`) : errMsg;
            return callback(err);
          }
          return callback({
            message: errMsg
          });
        }

        extraFiles = opennedFiles.opennedFiles;
        symlinksToCreate = opennedFiles.symlinks;
        callback(null);
      });
    },
    function(callback) {
      if (metadata.packagesSequence.length === 0) {
        extraFiles.push(metadata.exe);
      }

      async.parallel(
        metadata.entrypointArgs.map(a =>
          asyncCallback => {
            fs.lstat(a, (err, stats) => {
              if (!err && stats.isFile()) {
                extraFiles.push(a);
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
      const copyExtraFiles = extraFiles.map(f => function(asyncCallback) {
        shell(`cp -r ${f} ${extraFilesPath}`, CHECK_STDERR_FOR_ERROR, err => {
          if (err) {
            return asyncCallback(err);
          }

          asyncCallback(null);
        });
      });

      async.parallel(copyExtraFiles, err => {
        if (err) {
          return callback({
            message: 'Failed to import files that process openned'
          });
        }

        callback(null);
      });
    },
    function(callback) {
      const dockerfileContent = [
        `FROM ${config.baseimage}`,
        `COPY packages /packages`,
        `COPY apt /apt`,
        `Run dpkg --purge apt`,
        `RUN rm -rf /var/lib/apt`,
        `RUN rm -rf /etc/apt`,
        `RUN cp -rf /apt/varlib /var/lib/apt`,
        `RUN cp -rf /apt/etc /etc/apt`,
        debFiles.map(deb => `RUN dpkg -i /packages/${deb}`).join('\n'),
        `RUN apt-get update || echo 'apt-get update failed, installing anyway'`,
        metadata.packagesSequence.length === 0 ? '' : `RUN apt-get install --no-install-recommends -f -y ${metadata.packagesSequence.join(' ')}`,
        extraFiles.map(f => `COPY extraFiles/${last(f, '/')} ${f}`).join('\n'),
        symlinksToCreate.map(({linkPath, realPath, pathToCreate}) => `${pathToCreate ? `RUN mkdir -p ${pathToCreate}\n` : ''}RUN ln -s ${realPath} ${linkPath} || echo ignoring symlink ${linkPath}`).join('\n'),
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
      // issue: nginx: , causing docker tagging to fail
      shell(`cd ${buildPath} && docker build -t dd-agent/${program.replace(/\W/g, '')} .`, CHECK_STDERR_FOR_ERROR, err => {
        if (err) {
          return callback({
            message: 'Failed to build Docker image'
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
