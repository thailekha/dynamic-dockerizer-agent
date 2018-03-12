import getos from 'getos';
import { Router } from 'express';
import async from 'async';
import { exec } from 'shelljs';

export function checkhostHandler() {
  const router = Router({mergeParams:true});

  router.get('/', (req, res) => {
    let osMsg, packageMsg;

    async.series([
      function(callback) {
        getos((err,os) => {
          if (err) {
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
        exec(`dpkg-query -W dpkg-repack build-essential apt-rdepends docker`, code => {
          if (code === 0) {
            packageMsg = 'All required packages installed';
          } else if  (code === 1) {
            packageMsg = `Not all required packages installed, please reprovision or manually make sure the following packages are installed: dpkg-repack build-essential apt-rdepends`;
          } else {
            return callback('Error validating packages');
          }

          callback(null);
        });
      }
    ],
    function(err) {
      if (err) {
        return res.status(500).json(err);
      }
      const message = `${osMsg}, ${packageMsg}`;
      res.json({message});
    });
  });

  return router;
}