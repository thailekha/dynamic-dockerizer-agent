import getos from 'getos';
import { Router } from 'express';
import async from 'async';
import { exec } from 'shelljs';

export function checkhostHandler() {
  const router = Router({mergeParams:true});

  router.get('/', (req, res, next) => {
    let osMsg, packageMsg;

    async.series([
      function(callback) {
        getos((err,os) => {
          if (err) {
            const errMsg = 'Failed to get OS';
            err.message = err.message ? (err.message += `\n${errMsg}`) : errMsg;
            return callback(err);
          }

          if (os.os === 'linux' && os.dist === 'Ubuntu Linux' && os.codename === 'trusty') {
            osMsg = `Host OS validated, ${JSON.stringify(os)}`;
          } else {
            osMsg = `This project has been tested on Ubuntu trusty only. The detected release is ${JSON.stringify(os)}, so use this project at your own risk`;
            // res.status(501).json({message});
          }
          callback(null);
        });
      },
      function(callback) {
        exec(`dpkg-query -W dpkg-repack build-essential apt-rdepends docker`, (code, _, stderr) => {
          if ( !(code === 0 || code === 1) || stderr ) {
            return callback({
              message: 'Failed to validate required packages'
            });
          }

          if (code === 0) {
            packageMsg = 'All required packages installed';
          } else {
            //code === 1
            packageMsg = `Not all required packages installed, please reprovision or manually make sure the following packages are installed: dpkg-repack build-essential apt-rdepends`;
          }

          callback(null);
        });
      }
    ],
    function(err) {
      if (err) {
        return next(err);
      }
      const message = `${osMsg}, ${packageMsg}`;
      res.json({message});
    });
  });

  return router;
}