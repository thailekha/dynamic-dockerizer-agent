function UnauthorizedError(message) {
  this.name = 'UnauthorizedError';
  this.message = message || 'Unauthorized Error';
  this.code = 401;
  // this.stack = (new Error()).stack;
}

UnauthorizedError.prototype = Object.create(Error.prototype);
UnauthorizedError.prototype.constructor = UnauthorizedError;

export default UnauthorizedError;