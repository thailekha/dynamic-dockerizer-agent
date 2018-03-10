import { Router } from 'express';
import config from '../config.json';
import jwtAuthenticate from '../middleware/jwt-authenticate';
import shortid from 'shortid';

const router = Router({mergeParams:true});

export default keyv => {
  router.use(jwtAuthenticate({ secret: config.auth.secret }));

  router.get('/status/:progresskey', (req, res) => {
    keyv
      .get(req.params.progresskey)
      .then(progress => {
        if (typeof progress === 'undefined') {
          return res.status(500).json({'message': 'Cannot find progress key'});
        }
        res.json({status: progress});
      });
  });

  router.get('/generate', (req, res) => {
    console.log('Generating');
    res.json({key: shortid.generate()});
  });

  return router;
};