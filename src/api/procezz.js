import {parseNetstat, getProcessMetadata, convert, getOpennedFiles} from './procezz/index';

export function procezzHandler(router, {IGNORED_PORTS, IGNORED_PROGRAMS}) {
  router.get('/', (req, res) => {
    parseNetstat(IGNORED_PORTS, IGNORED_PROGRAMS, null, (err, processes) => {
      if (err) {
        return res.status(404).json(err);
      }
      res.json(processes);
    });
  });

  router.get('/:pid/metadata', (req, res) => {
    getProcessMetadata(req.params.pid, (err, metadata) => {
      if (err) {
        return res.status(404).json(err);
      }
      res.json(metadata);
    });
  });

  router.get('/:pid/convert', (req, res) => {
    convert(IGNORED_PORTS, IGNORED_PROGRAMS, req.params.pid, (err, dockerfile) => {
      if (err) {
        return res.status(404).json(err);
      }
      res.json(dockerfile);
    });
  });

  router.get('/:pid/opennedfiles', (req, res) => {
    getOpennedFiles(req.params.pid, (err, opennedfiles) => {
      if (err) {
        return res.status(404).json(err);
      }
      res.json(opennedfiles);
    });
  });
}