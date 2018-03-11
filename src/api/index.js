import { procezzHandler } from './procezz';
import { checkhostHandler } from './checkhost';
import progress from './progress';
import Keyv from 'keyv';

const keyv = new Keyv();

export default function buildAPI(server) {
  const IGNORED_PORTS = ['22','111', `${server.server.address().port}`];
  const IGNORED_PROGRAMS = ['rpc.statd'];

  server.use('/checkhost', checkhostHandler());
  server.use('/process', procezzHandler({IGNORED_PORTS, IGNORED_PROGRAMS}, keyv));
  server.use('/progress', progress(keyv));
}