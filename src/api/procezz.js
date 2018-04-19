import {parseNetstat, inspectProcess, convert} from './procezz/index';
import progress from '../middleware/progress';
import { Router } from 'express';

export function procezzHandler({IGNORED_PORTS, IGNORED_PROGRAMS}, keyv) {
  const router = Router({mergeParams:true});
  router.use(progress(keyv));

  /**
    * @swagger
    * definition:
    *   processFromNetstat:
    *     properties:
    *       port: { type: string }
    *       pid: { type: string }
    *       program: { type: string }
    * /processes/:
    *   get:
    *     tags:
    *       - Processes
    *     summary: 'Get all TCP processes'
    *     description:
    *     operationId: getProcesses
    *     produces:
    *       - application/json
    *     responses:
    *       '200':
    *         description: 'Sucessfully get processes'
    *         schema:
    *             type: object
    *             properties:
    *               processes:
    *                 type: array
    *                 items: $ref "#/definitions/processFromNetstat"
    *       '500': { description: 'Failed to gather processes listening on network' }
    */
  router.get('/', (req, res, next) => {
    parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, null, (err, processes) => {
      if (err) {
        return next(err);
      }
      res.json(processes);
    });
  });

  /**
    * @swagger
    * /processes/{pid}:
    *   get:
    *     tags:
    *       - Processes
    *     summary: 'Inspect a process'
    *     description:
    *     operationId: inspectProcess
    *     produces:
    *       - application/json
    *     responses:
    *       '200':
    *         description: 'Ok'
    *         schema:
    *             type: object
    *             properties:
    *                 cmdline:
    *                     type: string
    *                 exe:
    *                     type: string
    *                 bin:
    *                     type: string
    *                 entrypointCmd:
    *                     type: array
    *                     example: ["nginx"]
    *                 entrypointArgs:
    *                     type: array
    *                     example: ["-g 'daemon off'"]
    *                 cwd:
    *                     type: string
    *                     example: "/"
    *                 packagesSequence:
    *                     type: array
    *                     example: ["nginx"]
    */
  router.get('/:pid', (req, res, next) => {
    req.connection.setTimeout( 1000 * 60 * 100 );

    inspectProcess(keyv, req.headers['x-dd-progress'], req.params.pid, (err, metadata) => {
      keyv.delete(req.headers['x-dd-progress']);
      if (err) {
        return next(err);
      }
      res.json(metadata);
    });
  });

  /**
    * @swagger
    * /processes/{pid}/convert:
    *   get:
    *     tags:
    *       - Processes
    *     summary: 'Convert a process to Docker image'
    *     description:
    *     operationId: convertProcess
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
    *                     example: "Process 1234 converted to Docker image"
    */
  router.get('/:pid/convert', (req, res, next) => {
    req.connection.setTimeout( 1000 * 60 * 100 );

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