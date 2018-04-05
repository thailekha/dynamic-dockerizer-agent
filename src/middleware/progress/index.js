export default keyv => {

  if (!keyv) {
    throw new Error('Undefined keyv object when setup progress middleware');
  }

  function middleware(req, _, next) {
    if (req.headers['x-dd-progress']) {
      return keyv
        .set(req.headers['x-dd-progress'], 0)
        .then(() => {
          next(null);
        });
    }
    next(null);
  }

  return middleware;
};