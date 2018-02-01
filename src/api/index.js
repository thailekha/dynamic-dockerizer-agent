import { Router } from 'express';
import { procezzHandler } from './procezz';

export default function buildAPI(server) {
  const IGNORED_PORTS = ['22','111', `${server.server.address().port}`];
  const IGNORED_PROGRAMS = ['rpc.statd'];

  const router = Router({mergeParams:true});
  procezzHandler(router, {IGNORED_PORTS, IGNORED_PROGRAMS});

  server.use('/process', router);
}