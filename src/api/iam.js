import { Router } from 'express';
import {verifyIam} from './iam/index';
import {creds} from '../lib/util';

const router = Router({mergeParams:true});

/**
  * @swagger
  * definition:
  *   verifyIamParams:
  *     properties:
  *       accessKeyId: { type: string }
  *       secretAccessKey: { type: string }
  *       userName: { type: string }
  * /iam/verify:
  *   post:
  *     tags:
  *       - IAM
  *     summary: 'Verify an IAM credential'
  *     description:
  *     operationId: verifyIam
  *     produces:
  *       - application/json
  *     parameters:
  *       - schema: { $ref: '#/definitions/verifyIamParams' }
  *         in: body
  *         name: 'IAM credential'
  *         type: object
  *         description: 'The IAM credential to be verified'
  *         required: true
  *     responses:
  *       '200': { description: 'Valid AWS IAM' }
  *       '404': { description: 'Invalid AWS IAM' }
  */
router.post('/verify', (req, res) => {
  verifyIam(creds(req), req.body.userName, (err,data) => {
    if (err) {
      return res.status(404).send(err);
    }
    res.json(data);
  });
});

export default router;