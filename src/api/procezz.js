import {parseNetstat, inspectProcess, convert} from './procezz/index';
import progress from '../middleware/progress';
import { Router } from 'express';

export function procezzHandler({IGNORED_PORTS, IGNORED_PROGRAMS}, keyv) {
  const router = Router({mergeParams:true});
  router.use(progress(keyv));

  /**
    * @swagger
    * /process/:
    *   get:
    *     tags:
    *       - process
    *     summary: 'Get all TCP processes'
    *     description:
    *     operationId: getProcesses
    *     produces:
    *       - application/json
    *     responses:
    *       '200': { description: 'Sucessfully get processes' }
    *       '404': { description: 'Error netstat' }
    */
  router.get('/', (req, res, next) => {
    parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, null, (err, processes) => {
      if (err) {
        return next(err);
      }
      res.json(processes);
    });
  });

  router.get('/:pid', (req, res, next) => {
    inspectProcess(keyv, req.headers['x-dd-progress'], req.params.pid, (err, metadata) => {
      keyv.delete(req.headers['x-dd-progress']);
      if (err) {
        return next(err);
      }
      res.json(metadata);
    });
  });

  router.get('/:pid/convert', (req, res, next) => {
    req.connection.setTimeout( 1000 * 60 * 10 );

    convert(keyv, req.headers['x-dd-progress'], IGNORED_PORTS, IGNORED_PROGRAMS, req.params.pid, err => {
      keyv.delete(req.headers['x-dd-progress']);
      if (err) {
        return next(err);
      }
      res.json({message: `Process ${req.params.pid} converted to Docker image`});
    });
  });

  return router;
}