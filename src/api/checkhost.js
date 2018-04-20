import getos from 'getos';
import { Router } from 'express';
import async from 'async';
import { exec } from 'shelljs';

export function checkhostHandler() {
  const router = Router({mergeParams:true});

  /**
    * @swagger
    * /checkhost:
    *   get:
    *     tags:
    *       - Check host
    *     summary: 'Check OS of the host and required packages'
    *     description:
    *     operationId: checkHost
    *     produces:
    *       - application/json
    *     responses:
    *       '200':
    *         description: 'Ok'
    *         schema:
    *             type: object
    *             properties:
    *                 message:
    *                     type: string
    *                     example: "Host OS validated,Ubuntu Linux trusty 14.04, All required packages installed"
    */
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
          }
          callback(null);
        });
      },
      function(callback) {
        exec(`dpkg-query -W rsync build-essential apt-rdepends docker`, code => {
          if ( !(code === 0 || code === 1) ) {
            return callback({
              message: 'Failed to validate required packages'
            });
          }

          if (code === 0) {
            packageMsg = 'All required packages installed';
          } else {
            //code === 1
            packageMsg = `Not all required packages installed, please reprovision or manually make sure the following packages are installed: rsync build-essential apt-rdepends`;
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