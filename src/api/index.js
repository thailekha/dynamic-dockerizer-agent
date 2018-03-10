import { Router } from 'express';
import { procezzHandler } from './procezz';
import progress from './progress';
import Keyv from 'keyv';

const keyv = new Keyv();

export default function buildAPI(server) {
  const IGNORED_PORTS = ['22','111', `${server.server.address().port}`];
  const IGNORED_PROGRAMS = ['rpc.statd'];

  const router = Router({mergeParams:true});
  procezzHandler(router, {IGNORED_PORTS, IGNORED_PROGRAMS}, keyv);

  server.use('/process', router);
  server.use('/progress', progress(keyv));
}