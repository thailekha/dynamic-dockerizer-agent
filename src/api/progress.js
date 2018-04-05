import { Router } from 'express';
import shortid from 'shortid';

const router = Router({mergeParams:true});

export default keyv => {
  router.get('/status/:progresskey', (req, res, next) => {
    keyv
      .get(req.params.progresskey)
      .then(progress => {
        if (typeof progress === 'undefined') {
          return next({'message': 'Cannot find progress key'});
        }
        res.json({status: progress});
      });
  });

  router.get('/generate', (req, res) => {
    res.json({key: shortid.generate()});
  });

  return router;
};