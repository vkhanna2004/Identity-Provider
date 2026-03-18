const errorHandler = (err, req, res, next) => {
    console.error('[Unhandled Error]:', err);
  
    // Standardized error response
    const statusCode = err.statusCode || 500;
    const message = statusCode === 500 ? 'Internal Server Error' : err.message;
  
    res.status(statusCode).json({
      status: 'error',
      statusCode,
      message
    });
  };
  
export default errorHandler;